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
#include <sys/wait.h>
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

void runchild();

int main()
{
    if( getuid()!=0 ) {
        fprintf(stderr, "Not running under root (fakeroot-ng not running)\n");

        return 1;
    }

    pid_t child = fork();
    if(child < 0) {
        perror("Fork failed");

        return 1;
    }

    if( child==0 ) {
        runchild();

        return 2;
    }

    int status;
    if( waitpid(child, &status, 0)<0 ) {
        perror("Waitpid failed");

        return 1;
    }

    if( WIFEXITED(status) ) {
        fprintf(stderr, "Error: child process exit normally with return %d\n", WEXITSTATUS(status));

        return 2;
    }

    if( WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL ) {
        printf("Child killed (as expected)\n");

        if( getuid()!=0 ) {
            fprintf(stderr, "Not running under root (fakeroot-ng crashed)\n");

            return 1;
        }

        return 0;
    }

    if( WIFSIGNALED(status) ) {
        fprintf(stderr, "Error: child process killed by signal %d\n", WTERMSIG(status) );

        return 2;
    }

    fprintf(stderr, "Error: Child process exit with unparsed status %x\n", status);
    return 2;
}

void runchild()
{
    // Make sure fakeroot-ng has buffers in this process
    char filename[] = "/tmp/fakeroot-ng-test.XXXXXX";
    int fd = mkstemp(filename);

    if( fd<0 ) {
        perror("Failed to create temporary file");
        return;
    }

    if( fchownat(fd, "", 1, 2, AT_EMPTY_PATH)<0 ) {
        perror("Failed to change ownership of file");
        fprintf(stderr, "Are we running through fakeroot-ng?\n");

        unlink(filename);
        return;
    }

    struct map fakeroot_maps[2];
    find_fakeroot_regions(fakeroot_maps);
    printf("Found two fakeroot regions:\n%08lx-%08lx\n%08lx-%08lx\n", fakeroot_maps[0].start, fakeroot_maps[0].end,
            fakeroot_maps[1].start, fakeroot_maps[1].end);

    unlink(filename);

    void *addr = mmap((void *)fakeroot_maps[0].start, fakeroot_maps[1].end - fakeroot_maps[0].start, PROT_READ|PROT_WRITE,
            MAP_FIXED|MAP_ANONYMOUS, -1, 0);

    fprintf(stderr, "Error: Still running after mmap that returned %p\n", addr);

    if(addr == MAP_FAILED) {
        perror("Mmaped failed");
    }
}
