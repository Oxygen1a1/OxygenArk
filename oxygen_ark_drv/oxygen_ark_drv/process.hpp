#pragma once
#include "base.hpp"
#include "R3.h"
#include "hide_process.h"
#include "_utils.hpp"
#include "module.hpp"
#pragma warning(disable : 4201)
/// <summary>
/// 主要用于询问进程的信息
/// </summary>
/// 
/// 
/// 
namespace kprocess {
#define MAX_PATH 260
	using DWORD = DWORD32;
	typedef struct  p_info_t {

		char name[MAX_PATH];
		DWORD pid;
		DWORD ppid;
		bool uaccess;
		char filecontractor[60];
		DWORD sid;
		wchar_t fpath[MAX_PATH];
		char stime[8];
		wchar_t cmdline[MAX_PATH];
	}p_info, * pp_info;


	typedef struct _thread_info_t {
		char tid[MAX_PATH];
		char startAddr[MAX_PATH];
		char priority[MAX_PATH];
		char ethread[MAX_PATH];
		char teb[MAX_PATH];
		char switchCount[MAX_PATH];
		char moduleName[MAX_PATH];
	}thread_info_t, * pthread_info_t;

	typedef struct _threads_info_t {
		int threadsCount;
		pthread_info_t info;
	}threads_info_t, * pthreads_info_t;

	typedef struct handle_info_t {
		UINT32 access;
		char handleType[MAX_PATH];
		char handleName[MAX_PATH];
		HANDLE handle;
		UINT_PTR handleObject;
		UINT32 ptrRef;
		UINT32 handleRef;
		BOOLEAN closeProtect;
	}*phandle_info_t;

	typedef struct handles_info_t {
		unsigned int count;
		phandle_info_t infos;
	}*phandles_info_t;

	typedef struct query_handle_t {
		HANDLE pid;
		phandles_info_t infos;
	}*pquery_handle_t;
	
	auto query_process_info(pp_info info, PEPROCESS process)->bool;
	auto terminate_process(HANDLE pid) -> NTSTATUS;
	auto query_threads_info(__inout pthreads_info_t info) -> NTSTATUS;
	auto hide_process(HANDLE pid) -> bool;
	auto query_threads_tid(HANDLE pid) -> HANDLE*;
	auto query_process_handle_count(HANDLE pid) -> unsigned int;
	auto query_process_handles(HANDLE pid, phandles_info_t infos) -> bool;
}