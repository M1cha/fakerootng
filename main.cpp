#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "parent.h"

int parse_options( int argc, char *argv[] )
{
    int opt;

    while( (opt=getopt(argc, argv, "+p:d" ))!=-1 ) {
        switch( opt ) {
        case 'p':
            break;
        case '?':
            /* Error in parsing */
            return -1;
            break;
        default:
            fprintf(stderr, "%s: internal error: unrecognized option %c\n", argv[0], optopt);
            return -1;
            break;
        }
    }
    return optind;
}

int main(int argc, char *argv[])
{
    int opt_offset=parse_options( argc, argv );
    if( opt_offset==-1 )
        return 1;

    pid_t child=fork();
    if( child<0 ) {
        perror("Failed to create child process");

        return 2;
    }

    if( child==0 ) {
        /* We are the child */
        if( ptrace(PTRACE_TRACEME)!=0 ) {
            perror("Could not start trace");

            exit(2);
        }

        execvp(argv[opt_offset], argv+opt_offset);
        exit(2);
    }

    return process_children(child);
}
