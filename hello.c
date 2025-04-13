#include <stdio.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")

/*int zhy_add(int a, int b) {
	int arg1 = a;
	int arg2 = b;
	int ret = arg1 + arg2;
	return ret;
}*/


extern int zhy_add(int a, int b);
static void func1(void) {
	printf("add: 0x%x\n", zhy_add(4, 5));
}

void func2(void) {
	func1();
}

#pragma GCC pop_options

int main(int argc,
	 char **argv)
{

	printf("hello world\n");
	func2();
	return 0;
}
