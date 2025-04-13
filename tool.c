#include <stdio.h>
int zhy_add(int a, int b) {
	int arg1 = a;
	int arg2 = b;
	int ret = arg1 + arg2;
	return ret;
}

static void func1(void) {
	int ret = 28;
	printf("test: 0x%d", ret);
}

