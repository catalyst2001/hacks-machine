#include "hm_hook.h"

#include <Windows.h>

#define HM_JMP_ADDRESS_LENGTH (sizeof(void *))

#if defined(_M_IX86)
#define HM_JMP_OP_LENGTH (1) // x86 jmp opcode length
#include "hde/hde32.h"

#elif defined(_M_X64)
#define HM_JMP_OP_LENGTH (1) // x64 jmp opcode length
#include "hde/hde64.h"
#else

#error "Unsupported architecture!"
#endif

#define HM_JMP_NEDDED_SIZE (HM_JMP_OP_LENGTH + HM_JMP_ADDRESS_LENGTH)

void *operator new(size_t size) {
	return malloc(size);
}

void operator delete(void *p_block) {
	free(p_block);
}

HM_STATUS hm_mprotect(void *p_target_addr, size_t size, HM_MPROTECT *p_old_protect, HM_MPROTECT new_protect)
{



	return HM_OK;
}

HM_STATUS hm_trampoline_size_adjust(uint32_t *p_dst, void *p_target_addr, uint32_t needed_size)
{
	hde32s   dis;
	uint32_t offset;
	uint32_t instruction_len;
	uint8_t *p_target = (uint8_t *)p_target_addr;

	/* disassemble prologue */
	offset = 0;
	if (!needed_size)
		needed_size = HM_JMP_NEDDED_SIZE;

	while (offset < needed_size) {
		instruction_len = hde32_disasm(&p_target[offset], &dis);
		if (instruction_len == -1)
			return HM_DISASM_ERROR;

		offset += instruction_len;
	}
	*p_dst = offset;
	return HM_OK;
}

HM_STATUS hm_hook_func(hm_hook_s **p_dst_hk, void *p_target_addr, void **p_original, void *p_proxy_func, bool b_enable)
{
	HM_STATUS status;
	uint32_t trampoline_length;
	size_t trampoline_full_size;

	/* find trampoline size */
	status = hm_trampoline_size_adjust(&trampoline_length, p_target_addr, 0);
	if (status != HM_OK)
		return status;

	/* create hook object */
	hm_hook_s *p_hook = (hm_hook_s *)malloc(sizeof(hm_hook_s) + trampoline_length);
	if (!p_hook)
		return HM_OUT_OF_MEMORY;

	p_hook->trampoline_len = trampoline_length;

	/*
	 alloc and build trampoline 
	 1. trampoline_full_size = prologue bytes number + jump
	 2. copy source bytes to trampoline
	 3. write jump to source function_addr + HM_JMP_NEDDED_SIZE
	 4. change trampoline protection to EXEC|READ|WRITE
	*/
	trampoline_full_size = p_hook->trampoline_len + HM_JMP_NEDDED_SIZE;
	p_hook->p_trampoline = new uint8_t[trampoline_full_size];
	if (!p_hook->p_trampoline) {
		delete p_hook;
		return HM_OUT_OF_MEMORY;
	}

	/* copy prologue bytes to trampoline */
	memcpy(p_hook->p_trampoline, p_target_addr, p_hook->trampoline_len);
	memcpy(p_hook->backup_bytes, p_target_addr, p_hook->trampoline_len);
	
	/* write original function body address */
	intptr_t next_body_instuctions_address = (intptr_t)p_target_addr + p_hook->trampoline_len;
	intptr_t trampoline_to_func_body_jump = ((intptr_t)p_hook->p_trampoline - next_body_instuctions_address);
	uint8_t *p_end_trampoline = &p_hook->p_trampoline[p_hook->trampoline_len];
	
	/* build jump */
	// jmp <address>
	*p_end_trampoline = 0xE9;
	p_end_trampoline++;
	*((intptr_t *)p_end_trampoline) = trampoline_to_func_body_jump;

	/* change protection */
	if (!VirtualProtect(p_hook->p_trampoline, trampoline_full_size, PAGE_EXECUTE_READWRITE, NULL)) {
		delete p_hook->p_trampoline;
		delete p_hook;
		return HM_PROTECT_FAILED;
	}

	/* 
	 write jump in soucre function prologue to proxy function
	 1. compute offset from source function to trampoline
	 2. change protection to EXEC|READ|WRITE
	 3. write jump
	 4. change to previous protection
	*/
	uint8_t *p_target_addr_ub = (uint8_t *)p_target_addr;
	intptr_t jump_from_source_to_proxy_offset = ((intptr_t)p_proxy_func - (intptr_t)p_target_addr);

	DWORD old_protect;
	VirtualProtect(p_target_addr, p_hook->trampoline_len, PAGE_EXECUTE_READWRITE, &old_protect);
	*p_target_addr_ub = 0xE9;
	*((intptr_t *)p_target_addr_ub) = jump_from_source_to_proxy_offset;
	VirtualProtect(p_target_addr, p_hook->trampoline_len, old_protect, &old_protect);

	p_hook->is_enabled = b_enable;
	

	/* original = trampoline start address */
	*p_original = p_hook->p_trampoline;
	return HM_OK;
}
