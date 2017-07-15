#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
void timeout(){
    write(1,"timeout!\n",9);
    exit(0);
}
 
void init(){
    alarm(30);
    signal(SIGALRM,timeout);
}
 
void menu(){
    puts("welcome to my servvvvvvvvvvvvver!!!!!");
    puts("here you can:");
    puts("1.get time");
    puts("2.get flag");
    fflush(0);
}
 
void get_time(){
    system("TZ=CST-8 date");
}
 
void get_flag(){
    char buffer[0x100];
    puts("give me flag!");
    fflush(0);
    read(0,buffer,0x100);
    printf("ok, flag is ");
    printf(buffer);
    printf(":)\n");
    fflush(0);
}
 
int main(int argc,char* argv[]){
    init();
    char select[2];
    while(1){
        menu();
        read(0,&select,2);
        switch(atoi(&select)){
        case 1:
            get_time();
            break;
        case 2:
            get_flag();
            break;
        default:
            printf("???\n");
            fflush(0);
        }
    }
}
