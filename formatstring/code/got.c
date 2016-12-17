#include <stdio.h>
int main(){
    char buf[100];
    while (1){
        scanf("%s",buf);
        printf(buf);
        puts("/bin/sh");
    }
}
