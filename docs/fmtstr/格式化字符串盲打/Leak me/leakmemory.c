#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 
int main(int argc, char *argv[])
{
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    int flag;
    char buf[1024];
    FILE* f;
    puts("What's your name?");
    fgets(buf, 1024, stdin);
    printf("Hi, ");
    printf("%s",buf);
    putchar('\n');
    flag = 1;
    while (flag == 1)
    {
        puts("Do you want the flag?");
        memset(buf,'\0',1024);
        read(STDIN_FILENO, buf, 100);
        if (!strcmp(buf, "no\n"))
        {
            printf("I see. Good bye.");
            return 0;
        }
        else
        {   
            printf("Your input isn't right:");
            printf(buf);
            printf("Please Try again!\n");
        }
        fflush(stdout);
    }
    return 0;
}