int main(){
char buf[64];
write(1,"pwn me\n",8);
read(0,buf,256);
}
