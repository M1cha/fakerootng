/* This is a tool for exercising the various system calls we would potentially like to emulate with fakeroot-ng.
 * By definition, this tool should produce identical results when running under fakeroot-ng and when running as
 * root.
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main( int argc, char *argv[] )
{
    uid_t uid=getuid(), euid=geteuid();
    gid_t gid=getgid(), egid=getegid();

    printf("uid %d euid %d gid %d egid %d\n", uid, euid, gid, egid );

    return 0;
}
