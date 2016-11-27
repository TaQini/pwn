#include <stdio.h>

void attackme(){
    printf("Mom, someone attacked me T_T\n");
}

int main(){
    char name[64];
    printf("Input you name: ");
    scanf("%s", name);
    printf("Hello, %s\n", name);
    return 0;
}
