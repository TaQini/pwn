#include <windows.h>
#include <stdio.h>
#define DLL_NAME "user32.dll"
int main(){
	BYTE* ptr;
	int pos,addr;
	HINSTANCE handle;
	BOOL done_flag = FALSE;
	handle = LoadLibrary(DLL_NAME);
	if (!handle){
		printf("load dll error!\n");
		exit(0);
	}
	ptr = (BYTE*)handle;
	for(pos=0;!done_flag;pos++){
		try{
			if(ptr[pos]==0xFF && ptr[pos+1]==0xE4){
				int addr = (int)ptr + pos;
				printf("OPCEODE finded at 0x%08x\n",addr);
			}
		}
		catch(...){
			int addr = (int)ptr + pos;
			printf("END OF 0x%08x\n",addr);
			done_flag = TRUE;
		}
	}
}
