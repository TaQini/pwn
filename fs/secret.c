int main(){
    static int secret = 666;
    char buf[256];
    scanf("%s",buf);
    printf(buf);
    printf("secret: %d\n", secret);
}
