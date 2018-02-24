#include <stdio.h>

void entry(void)
{
	FILE *f = fopen("/tmp/test", "w");

	if (!f)
		return;

	fprintf(f, "Hello from injected thread!\n");

	fclose(f);
}
