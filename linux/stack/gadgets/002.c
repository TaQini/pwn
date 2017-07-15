#include <stdio.h>
int main() {
    char buf[128];
    read(0, buf, 512);
    write(1, "Hello, World\n", 13);
}
