int main(){
    char buf[24];
    write(1,"overflow me\n",12);
    read(0,buf,256);
}
