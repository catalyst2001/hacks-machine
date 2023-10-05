#pragma once
#include <stdlib.h>
#include <stdint.h>

struct hm_list_entry_s {
	hm_list_entry_s *p_last;
	hm_list_entry_s *p_next;
};

enum HM_STATUS {
	HM_OK = 0,
	HM_OUT_OF_MEMORY,
	HM_DISASM_ERROR,
	HM_PROTECT_FAILED,
};

struct hm_module_info_s {
	void *p_module_base;
	size_t image_size;
	void *p_image_base;
	size_t data_size;
	void *p_data_base;
};

/* MODULES */
bool       hm_get_module_info(hm_module_info_s *p_dst_info, const char *p_name);

/* QUERY MEMORY INFORMATION */
bool       hm_region_is_readonly(void *p_target_addr, size_t size);
bool       hm_region_is_execute(void *p_target_addr, size_t size);
bool       hm_region_is_no_access(void *p_target_addr, size_t size);
bool       hm_is_valid_ptr(void *p_target_addr);

enum HM_MPROTECT {
	HM_MPROTECT_NO_PROTECT = 0,
	HM_MPROTECT_EXECUTE_READ_WRITE,
	HM_MPROTECT_EXECUTE_READ,
	HM_MPROTECT_READONLY
};

HM_STATUS  hm_mprotect(void *p_target_addr, size_t size, HM_MPROTECT *p_old_protect, HM_MPROTECT new_protect);

/* HOOKS */
struct hm_hook_group_s {
	const char *p_name;
	hm_list_entry_s *p_start;
	hm_list_entry_s *p_end;
};

struct hm_hook_s {
	bool is_enabled;
	size_t trampoline_len;
	uint8_t *p_trampoline;
	uint8_t backup_bytes[];
};

enum HM_HOOK_PROXY_CALL_CONV : char {
	HM_HOOK_PROXY_CALL_CONV_DEFAULT = 0,
	HM_HOOK_PROXY_CALL_CONV_TO_STDCALL,
	HM_HOOK_PROXY_CALL_CONV_TO_CDECL
};

HM_STATUS  hm_trampoline_size_adjust(uint32_t *p_dst, void *p_target_addr, uint32_t needed_size);

HM_STATUS  hm_hook_func(hm_hook_s **p_dst_hk, void *p_target_addr, void **p_original, void *p_proxy_func, bool b_enable);
HM_STATUS  hm_hook_vtable(hm_hook_s **p_dst_hk, void *p_target_addr, void **p_original, void *p_proxy_func, HM_HOOK_PROXY_CALL_CONV call_format, bool b_enable);
HM_STATUS  hm_hook_enable(hm_hook_s *p_src_hk, bool b_active);
bool       hm_hook_is_enabled(hm_hook_s *p_src_hk);
HM_STATUS  hm_hook_remove(hm_hook_s **p_dst_hk);

/* EMITTER */
//template <size_t capacity>
//class hm_emiter_fixed {
//	size_t size;
//	hm_ubyte data[capacity];
//
//public:
//
//	hm_emiter_fixed() : size(0), {}
//		~hm_emiter_fixed() {}
//
//	bool emit_bytes(hm_ubyte *p_bytes, size_t len) {
//		//size_t rem_size = 
//
//
//	}
//
//	// example: "\x00\x11\x22\xFF"
//	bool emit_bytes_string(size_t *p_dst_writed, const char *p_str) {
//		size_t i;
//		for (i = 0; p_str[i]; i++) {
//			if (size == capacity) {
//				*p_dst_writed = i;
//				return false;
//			}
//			data[size++] = p_str[i];
//		}
//		*p_dst_writed = i;
//		return true;
//	}
//
//	// example: "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"
//	bool emit_string(const char *p_str) {
//
//	}
//
//	bool emit1(int byte) {
//
//	}
//
//	bool emit2(int byte) {
//
//	}
//
//	bool emit3(int byte) {
//
//	}
//
//	bool emit4(int byte) {
//
//	}
//};
//
//class hm_emit_buildin {
//	uint8_t *p_buffer;
//	uint32_t pos;
//public:
//
//	hm_emit_buildin() : p_buffer(NULL), pos(0) {}
//	hm_emit_buildin(uint8_t *p_dst) : p_buffer(p_dst), pos(0) {}
//	hm_emit_buildin(uint8_t *p_dst, uint32_t start_pos) : p_buffer(p_dst), pos(start_pos) {}
//	~hm_emit_buildin() {}
//
//	__forceinline void emit1(int byte) { p_buffer[pos++] = byte; }
//	__forceinline void emit2(int p1, int p2) {
//		emit1(p1);
//		emit1(p2);
//	}
//
//	__forceinline void emit3(int p1, int p2, int p3) {
//		emit1(p1);
//		emit1(p2);
//		emit1(p3);
//	}
//
//	__forceinline void emit4(int p1, int p2, int p3, int p4) {
//		emit1(p1);
//		emit1(p2);
//		emit1(p3);
//		emit1(p4);
//	}
//
//	__forceinline void emit5(int p1, int p2, int p3, int p4, int p5) {
//		emit1(p1);
//		emit1(p2);
//		emit1(p3);
//		emit1(p4);
//		emit1(p5);
//	}
//
//	__forceinline void     set_pos(uint32_t _p) { pos = _p; }
//	__forceinline uint32_t get_pos()            { return pos; }
//};