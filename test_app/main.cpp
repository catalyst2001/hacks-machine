#include <stdio.h>
#include "hm_hook.h"

#pragma optimize("g", off)

typedef int (__cdecl *printf_pfn)(char const* const _Format, ...);
hm_hook_s *p_printf_hk;
printf_pfn p_printf;

int printf_hk(char const* const _Format, ...)
{
	return p_printf(_Format);
}

int main()
{
	if (hm_hook_func(&p_printf_hk, printf, (void **)&p_printf, printf_hk, true) != HM_OK)
		return 1;
	

	printf("Hello world!\n");
	return 0;
}