#include <stdio.h>
#include <unistd.h>

void get_message(char *name);

int volatile main()
{
    setbuf(stdout, 0);
    
    char name[100];

    printf("please enter your name:");
    
    gets(name);
    printf("Welcome to participate the 429 ctf!\n");

    get_message(name);

    printf("thank you!\n");

    return 0;
}

void get_message(char * name)
{
    char message[100];
    printf(name);
    printf(", can you leave me some messages:");
    gets(message);
}
