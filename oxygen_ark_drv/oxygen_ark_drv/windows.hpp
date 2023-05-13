#pragma once
#include "base.hpp"
#include "_utils.hpp"
#include "module.hpp"
#include "process.hpp"
namespace windows {
	using HWND = void*;
	using BOOL = bool;
#define MAX_PATH 260


	//专门用于询问timers


	typedef struct _HEAD{
	void* unk[3];
	void* threadInfo;
	}HEAD;

	
	typedef struct timer_t{

		HEAD head;//0
		void* pfn;//20
		DWORD32 elapse;//28
		DWORD32 flags;//2c
		DWORD32 unkFlags;//30
		DWORD32 elapse1;//34
		char padding[0x10];//38
		LIST_ENTRY list1;//链接的是gtmrListHead //48
		void* spwnd;//58
		UINT64 id;//60
		void* threadObject;//68
		LIST_ENTRY list2;//Hash链接gTimerHashTable

	}*ptimer_t;
	typedef struct window_info_t {

		HWND hwnd;
		HANDLE pid;
		HANDLE tid;
		BOOL isVisible;
		char titile[MAX_PATH];
	}*pwindow_info_t;

	typedef struct windows_info_t {
		int count;
		pwindow_info_t infos;

	}*pwindows_info;

	typedef struct timer_info_t {
		void* timer_object;
		void* pfn;
		unsigned int elapse;
		char modules[MAX_PATH];                                              
	}*ptimer_info_t;

	typedef struct timers_info_t {
		int count;
		ptimer_info_t infos;
	}*ptimers_info_t;

	typedef struct query_timers_t {

		HANDLE pid;
		ptimers_info_t timers_info;

	}*pquery_timers_t;


	//用于查找时候 挂入链表
	typedef struct find_list_t {

		LIST_ENTRY list;
		ptimer_t timer;

	}*pfind_list_t;
	auto query_timer_count(HANDLE pid) -> unsigned int;

	auto query_process_timer(__inout pfind_list_t head, HANDLE pid) -> void;

}