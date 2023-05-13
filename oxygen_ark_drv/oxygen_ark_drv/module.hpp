#pragma once
#include "base.hpp"
#include "process.hpp"

namespace Module {
#define MAX_PATH 260

	typedef struct module_info_t {
		char path[MAX_PATH];
		char moduleStart[MAX_PATH];
		char moduleEnd[MAX_PATH];
		char companyName[MAX_PATH];
	}*pmodule_info_t;

	typedef struct modules_info_t {
		HANDLE pid;
		int moduleCount;
		pmodule_info_t modules;
	}*pmodules_info_t;

	auto enum_process_modules(PEPROCESS process,pmodules_info_t moduleInfos) -> bool;
	auto query_process_module_count(PEPROCESS process) -> UINT64;
	auto enum_process_modules(PEPROCESS process, pmodules_info_t moduleInfos) -> bool;
	auto get_file_module_name(PEPROCESS process, UINT_PTR addr, __out char* moduleName) -> bool;
	auto get_file_module_name(HANDLE pid, UINT_PTR addr, __out char* moduleName) -> bool;
}