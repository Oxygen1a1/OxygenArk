#pragma once
#include "base.hpp"
#include "./utils/hde64.h"

namespace _Utils {


	typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
	{
		//这个应该是LONG 因为有符号扩展
		PLONG ServiceTableBase;
		PULONG ServiceCounterTableBase;
		ULONG NumberOfServices;
		PUCHAR ParamTableBase;
	} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;


	

	auto find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask) -> unsigned long long;
	auto find_pattern_image(unsigned long long base, const char* pattern, const char* mask, const char* name = ".text") -> unsigned long long;
	auto get_section_address(unsigned long long addr, const char* section_name, __out unsigned long* size) -> unsigned long long;
	auto process_force_enum_by_name(const wchar_t* szProcessName) -> ULONG;
	auto _atoi(char* asci,int base=10) -> LONG64;
	auto _chartow(wchar_t* dest, const char* source) -> void;
	auto _wtochar(char* dest, const wchar_t* source)->void;
	auto find_module_base(const char* module_name) -> void*;
	auto find_module_export(void* base, const char* name) -> void*;
	auto _ualloc(size_t size, ULONG protect=PAGE_EXECUTE_READWRITE) -> void*;
	auto find_module_export_wow64(PEPROCESS process, ULONG base, const char* name) -> ULONG;
	auto find_module_base_wow64(PEPROCESS process, const wchar_t* dll_name) -> ULONG;
	auto find_module_export(PEPROCESS process, UINT_PTR base, const char* name) -> UINT_PTR;
	auto find_module_base(PEPROCESS process, const wchar_t* name) -> UINT_PTR;
	auto get_sssdt() -> UINT_PTR;
	auto get_ssdt() -> UINT_PTR;
	auto get_nt_func(const char* name) -> UINT_PTR;
	auto change_pre_mode(MODE m) -> MODE;
	auto resume_pre_mode(MODE o) -> void;
}