#include "Windows.h"
#include <stdio.h>
int main() {
	LoadLibrary("user32.dll");
	MessageBoxA(0, "....", "TaQini:", 0);
	ExitProcess(0);
}