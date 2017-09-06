#include <stdio.h>
#include <stdlib.h>

#define USE_LIBC_FGETS
/* #define USE_LIBC_FREAD */
/* #define USE_POSIX_READ */

#define BUFF_SIZE 300

int main(int argc, char* argv[]){
    if (argc != 2) {
        printf("Invalid input\n");
        exit(1);
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL){
        printf("Cannot open file!\n");
        exit(1);
    }

    char buffer[BUFF_SIZE];

#if defined(USE_LIBC_FGETS)
    fgets(buffer, BUFF_SIZE, fp);
#elif defined(USE_LIBC_FREAD)
    fread(buffer, 1, BUFF_SIZE, fp);
#elif defined(USE_POSIX_READ)
    read(fileno(fp), buffer, BUFF_SIZE);
#endif

    if(buffer[BUFF_SIZE-1] == 'a')
        printf("Path 1\n");
    else
        printf("Path 2\n");

    close(fp);

    return 0;
}
