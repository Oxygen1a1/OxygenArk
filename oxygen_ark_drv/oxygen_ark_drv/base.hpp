#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "undoc_func.hpp"


#define ONLY_DEBUG_BREAK DEBUG_BREAK()
//如果debug版本 直接断下
inline void DEBUG_BREAK(void) {

#ifdef DBG
	__debugbreak();
#endif // DBG

}


#pragma warning (disable : 4996)
using u64 = unsigned long long;
using u32 = unsigned long;
using u16 = unsigned short;
using u8 = unsigned char;
using s8 = char;

//在这里修改 到底是非分页 还是分页 以及NEW_FLAGS的
#define NEW_FLAGS 'Mnew'
#define POOL_FLAG PagedPool

void* operator new(size_t size);
void* operator new[](size_t size);
void operator delete(void* ptr);
void operator delete[](void* ptr);