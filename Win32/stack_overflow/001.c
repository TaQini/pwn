#include <stdio.h>
#include <string.h>
#define PASSWD "1234567"
int verify_passwd(char *passwd) {
	int authed;
	char buf[8];
	authed = strcmp(passwd, PASSWD);
	strcpy(buf, passwd);
	return authed;
}
int main() {
	int flag = 0;
	char passwd[8];
	while (1) {
		printf("pls input passwd: ");
		scanf("%s", passwd);
		flag = verify_passwd(passwd);
		if (flag) {
			printf("incorrect passwd! try again\n");
		}
		else {
			printf("right1\n");
			break;
		}
	}
}
