#include <stdio.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")

int add(int a, int b) {
	int ret = a + b;
	return ret;
}

void func1(void) {
	printf("add: 0x%x\n", add(4, 5));
}

void func2(void) {
	func1();
}

#pragma GCC pop_options

int main()
{

	printf("hello world\n");
	func2();
	return 0;
}
