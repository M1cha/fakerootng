#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>

size_t PAGE_SIZE;

struct maps_entry {
    uintptr_t start, end;
    unsigned int flags;
#define MAPS_READ 04
#define MAPS_WRITE 02
#define MAPS_EXEC 01
#define MAPS_SHARED 010
    char path[PATH_MAX];
};

struct maps_entry parse_entry(FILE *maps)
{
    struct maps_entry ret;
    off_t offset;
    int major, minor;
    int inode;
    char perms[5];
    char line[500];

    if( fgets(line, sizeof(line), maps)==NULL ) {
        memset( &ret, 0, sizeof(ret) );
        return ret;
    }

    int numparsed = sscanf(line, "%lx-%lx %4s %lx %x:%x %d %s", &ret.start, &ret.end, perms, &offset,
            &major, &minor, &inode, ret.path);

    if( numparsed<7 ) {
        memset( &ret, 0, sizeof(ret) );
        return ret;
    } else if( numparsed==7 ) {
        memset( ret.path, 0, sizeof(ret.path) );
    }

    ret.flags = 0;
    if(strchr(perms, 'r'))
        ret.flags |= MAPS_READ;
    if(strchr(perms, 'w'))
        ret.flags |= MAPS_WRITE;
    if(strchr(perms, 'x'))
        ret.flags |= MAPS_EXEC;
    if(strchr(perms, 's'))
        ret.flags |= MAPS_SHARED;

    return ret;
}

struct map {
    uintptr_t start;
    uintptr_t end;
};

void find_fakeroot_regions( struct map fakeroot_maps[] )
{
    int index=0;
    FILE *maps = fopen("/proc/self/maps", "rt");

    if( maps==NULL ) {
        perror("Couldn't open maps file");

        exit(2);
    }

    struct maps_entry entry;

    while( entry=parse_entry(maps), entry.start!=0 ) {
        if( entry.flags==(MAPS_READ|MAPS_EXEC|MAPS_SHARED) && strstr(entry.path, "/fakeroot-ng.")!=NULL ) {
            // We found the shared map
            assert(index<2);
            fakeroot_maps[index].start = entry.start;
            fakeroot_maps[index].end = entry.end;
            index++;
        } else if( entry.flags==(MAPS_READ|MAPS_WRITE|MAPS_EXEC) ) {
            // We probably found the private map
            assert(index<2);
            fakeroot_maps[index].start = entry.start;
            fakeroot_maps[index].end = entry.end;
            index++;
        }
    }

    assert(index==2);

    fclose(maps);
}

void checksuccess(const char *operation, int result)
{
    if(result!=0) {
        perror("ERROR: unmap failed");
        fprintf(stderr, "Failed to unmap test \"%s\"\n", operation);
        exit(1);
    }
}

void checksuccess_mmap(const char *test, void *base, int start, unsigned int length)
{
    unsigned int i;
    for( i=0; i<length; ++i )
        if( msync(base + (start+i)*PAGE_SIZE, PAGE_SIZE, MS_ASYNC)>=0 || errno!=ENOMEM ) {
            fprintf(stderr, "Region was not unmapped for test \"%s\"\n", test);
            void *failed_start = base + (start+i)*PAGE_SIZE;
            fprintf(stderr, "Failed region: %p-%p\n", failed_start, failed_start + PAGE_SIZE);
            exit(1);
        }
    if( mmap( base + start*PAGE_SIZE, length*PAGE_SIZE, PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 )
            ==MAP_FAILED )
    {
        perror("Remap failed");
        fprintf(stderr, "Failed to remap after test \"%s\"\n", test);

        exit(1);
    }
}

int main()
{
    PAGE_SIZE = getpagesize();

    // Try to control where the buffers will be
    void *bigregion = mmap( NULL, 20*PAGE_SIZE, PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 );
    if( bigregion == MAP_FAILED ) {
        perror("Failed to mmap region");
        exit(2);
    }

    // Create two holes
    munmap(bigregion + 3*PAGE_SIZE, 3*PAGE_SIZE);
    munmap(bigregion + 12*PAGE_SIZE, 3*PAGE_SIZE);

    // Make sure fakeroot-ng has buffers in this process
    char filename[] = "/tmp/fakeroot-ng-test.XXXXXX";
    int fd = mkstemp(filename);

    if( fd<0 ) {
        perror("Failed to create temporary file");
        return 1;
    }

    if( fchownat(fd, "", 1, 2, AT_EMPTY_PATH)<0 ) {
        perror("Failed to change ownership of file");
        fprintf(stderr, "Are we running through fakeroot-ng?\n");

        unlink(filename);
        return 2;
    }

    struct map fakeroot_maps[2];
    find_fakeroot_regions(fakeroot_maps);
    printf("Found two fakeroot regions:\n%08lx-%08lx\n%08lx-%08lx\n", fakeroot_maps[0].start, fakeroot_maps[0].end,
            fakeroot_maps[1].start, fakeroot_maps[1].end);

    unlink(filename);

    checksuccess("Unmap low region (nop)",
            munmap( (void *)fakeroot_maps[0].start, fakeroot_maps[0].end - fakeroot_maps[0].start ));
    checksuccess("Unmap high region (nop)",
            munmap( (void *)fakeroot_maps[1].start, fakeroot_maps[1].end - fakeroot_maps[1].start ));

    if( fakeroot_maps[0].end == fakeroot_maps[1].start ) {
        fprintf(stderr, "Fakeroot regions consecutive; skipping hole related tests\n");
    } else {
        const char *test_name;

        test_name = "Memory between regions";
        checksuccess(test_name,
                munmap( bigregion + 7*PAGE_SIZE, 2*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 7, 2 );

        test_name = "Low to middle";
        checksuccess(test_name,
                munmap( bigregion + 4*PAGE_SIZE, 4*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 6, 2 );

        test_name = "Middle to high";
        checksuccess(test_name,
                munmap( bigregion + 10*PAGE_SIZE, 5*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 10, 3 );

        test_name = "Low- to middle";
        checksuccess(test_name,
                munmap( bigregion + 1*PAGE_SIZE, 7*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 1, 2 );
        checksuccess_mmap(test_name, bigregion, 6, 2 );

        test_name = "Middle to high+";
        checksuccess(test_name,
                munmap( bigregion + 10*PAGE_SIZE, 7*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 10, 2 );
        checksuccess_mmap(test_name, bigregion, 15, 2 );

        test_name = "Low- to high";
        checksuccess(test_name,
                munmap( bigregion + 2*PAGE_SIZE, 12*PAGE_SIZE ));
        // Make sure unmap succeeded
        checksuccess_mmap(test_name, bigregion, 2, 1 );
        checksuccess_mmap(test_name, bigregion, 6, 6 );
    }

    return 0;
}
