#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int print_wait_status( int status, pid_t child )
{
    int exit = 0;

    if(WIFEXITED(status)) {
        printf("Child exit with return code %d\n", WEXITSTATUS(status));
        exit = 1;
    } else if(WIFSIGNALED(status)) {
        printf("Child terminated with signal %d%s\n", WTERMSIG(status), WCOREDUMP(status) ? " (core dumped)" : "");
        exit = 1;
    } else if(WIFSTOPPED(status)) {
        printf("Child stopped with signal %d\n", WSTOPSIG(status));
    } else
        printf("Unknown status %x\n", status);

    return exit;
}

int main()
{
    size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *map = mmap( NULL, 3*PAGE_SIZE, PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );

    if( map == MAP_FAILED ) {
        perror("mmap failed");

        return 1;
    }

    munmap( map+PAGE_SIZE, PAGE_SIZE );
    mprotect( map+2*PAGE_SIZE, PAGE_SIZE, PROT_NONE );

    pid_t child = fork();

    if( child<0 ) {
        perror("Failed to fork");

        return 2;
    }

    if( child==0 ) {
        ptrace(PTRACE_TRACEME);

        kill(getpid(), SIGUSR2);

        return 0;
    }

    int status;
    pid_t cpid = wait(&status);
    print_wait_status( status, cpid );

    char buffer[250];
    sprintf(buffer, "/proc/%d/mem", child);
    int mem_fd = open( buffer, O_RDWR );
    if( mem_fd<0 ) {
        perror("Failed to open /proc/../mem");
        return 3;
    }

    // Seek into an illegal location
    if( lseek( mem_fd, (size_t)map+PAGE_SIZE+10, SEEK_SET )<0 ) {
        perror("Seek to illegal location failed");
    } else {
        printf("Seek to illegal location is fine\n");
        errno=0;

        int numread = read( mem_fd, buffer, 10 );
        printf("Reading 10 bytes from illegal location returned %d (errno %d: %s)\n", numread, errno, strerror(errno));
    }

    if( lseek( mem_fd, (size_t)map+PAGE_SIZE-10, SEEK_SET )<0 ) {
        perror("Seek to legal location failed");
    } else {
        printf("Seek to legal location is fine\n");

        errno=0;
        int numread = read( mem_fd, buffer, 20 );
        printf("Reading 20 bytes from legal location containing only 10 returned %d (errno %d: %s)\n", numread, errno,
                strerror(errno));
    }

    if( lseek( mem_fd, (size_t)map, SEEK_SET )<0 ) {
        perror("Seek to legal location failed");
    } else {
        printf("Seek to legal location is fine\n");

        strcpy(buffer, "Hello, world\n");
        errno=0;
        int written = write( mem_fd, buffer, 13 );
        printf("Writing 13 bytes to legal read only location returned %d (errno %d: %s)\n", written, errno,
                strerror(errno));

        printf("Memory contains %c%c%c%c%c%c%c%c%c%c%c%c%c\n", map[0], map[1], map[2], map[3],
                map[4], map[5], map[6], map[7], map[8], map[9], map[10], map[11], map[12],
                map[13] );
    }

    strcpy( buffer, "Long placeholder text to make sure we actually read something" );
    if( lseek( mem_fd, (size_t)map, SEEK_SET )<0 ) {
        perror("Seek to legal location failed");
    } else {
        printf("Seek to legal location is fine\n");

        errno=0;
        int numread = read( mem_fd, buffer, 13 );
        printf("Reading 13 bytes from legal read only location returned %d (errno %d: %s)\n", numread, errno,
                strerror(errno));

        printf("Memory contains %c%c%c%c%c%c%c%c%c%c%c%c%c\n", map[0], map[1], map[2], map[3],
                map[4], map[5], map[6], map[7], map[8], map[9], map[10], map[11], map[12],
                map[13] );
    }

    strcpy( buffer, "Long placeholder text to make sure we actually read something" );
    if( lseek( mem_fd, (size_t)map+2*PAGE_SIZE, SEEK_SET )<0 ) {
        perror("Seek to legal location failed");
    } else {
        printf("Seek to legal location is fine\n");

        errno=0;
        int numread = read( mem_fd, buffer, 13 );
        printf("Reading 13 bytes from legal unreadable location returned %d (errno %d: %s)\n", numread, errno,
                strerror(errno));

        printf("Memory contains %c%c%c%c%c%c%c%c%c%c%c%c%c\n", map[0], map[1], map[2], map[3],
                map[4], map[5], map[6], map[7], map[8], map[9], map[10], map[11], map[12],
                map[13] );
    }

    ptrace(PTRACE_KILL, child);

    return 0;
}
