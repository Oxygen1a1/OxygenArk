#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "process.hpp"
#include "windows.hpp"
#include "inject.hpp"

namespace R3 {
#define CTL_QUERY_PROCESS CTL_CODE(0x8000,0X801,0,0)
#define CTL_TERMINATE_PROCESS CTL_CODE(0x8000,0X802,0,0)
#define CTL_HIDE_PROCESS CTL_CODE(0x8000,0X803,0,0)
#define CTL_QUERY_THREAD CTL_CODE(0x8000,0X804,0,0)
#define CTL_QUERY_MODULES CTL_CODE(0x8000,0X805,0,0)
#define CTL_QUERY_MODULES_COUNT CTL_CODE(0x8000,0X806,0,0)
#define CTL_QUERY_TIMERS_COUNT CTL_CODE(0x8000,0x807,0,0)
#define CTL_QUERY_TIMERS CTL_CODE(0x8000,0x808,0,0)
#define CTL_QUERY_HANDLES_COUNT CTL_CODE(0x8000,0x809,0,0)
#define CTL_QUERY_HANDLES CTL_CODE(0x8000,0x80a,0,0)
#define CTL_INJECT CTL_CODE(0x8000,0x80b,0,0)

#define MAX_PATH 260
	



	NTSTATUS init_device_and_symbolic(PDRIVER_OBJECT driver_object);
	void delete_device_and_symbolic(PDRIVER_OBJECT driver_object);

	inline UNICODE_STRING g_usDeviceName = RTL_CONSTANT_STRING(L"\\Device\\OxygenArk");
	inline UNICODE_STRING g_usSymbolicName = RTL_CONSTANT_STRING(L"\\??\\OxygenArk");
}
