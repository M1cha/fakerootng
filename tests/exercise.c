/* This is a tool for exercising the various system calls we would potentially like to emulate with fakeroot-ng.
 * By definition, this tool should produce identical results when running under fakeroot-ng and when running as
 * root.
 */

#include "../config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[] )
{
    uid_t uid=getuid(), euid=geteuid();
    gid_t gid=getgid(), egid=getegid();

    printf("uid %d euid %d gid %d egid %d\n", uid, euid, gid, egid );
    
    if( mkdir("testdir", 0777)==0 ) {
        printf("mkdir succeeded\n");
    } else {
        perror("mkdir failed");

        exit(1);
    }

    chdir("testdir");

    if( mknod( "file1", 0666 | S_IFREG, 0 )==0 ) {
        printf("file1 created using mknod\n");
    } else {
        perror("file1 not created");
    }

#if HAVE_OPENAT
    if( fchownat( AT_FDCWD, "file1", 0, 12, 0 )==0 ) {
        printf("file1 fchownat to 0,12\n");
    } else {
        perror("fchownat(file1, 0, 12) failed");
    }
#endif

    return 0;
}
