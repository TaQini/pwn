#include <stdio.h>
#include <time.h>
#include <stdlib.h>
//LET_ME_WIN!
int main(){
	int number;
	int guess;
	srand(time(0));
	guess = rand() % 100 + 1;
	while (1){
		scanf("%d", &number);
		if (number > guess){
			printf("less than %d.\n",number);
		}
		else if (number < guess){
			printf("more than %d.\n",number);
		}
		else{
			printf("RIGHT!\n");
			break;
		}
	}
	return 0;
}
