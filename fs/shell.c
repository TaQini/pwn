void giveshell(){
    system("/bin/sh");
}
int main(){
    char buf[256];
    scanf("%s",buf);
    printf(buf);
    return 0;
}
