#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "undoc_func.hpp"


#define ONLY_DEBUG_BREAK DEBUG_BREAK()
//���debug�汾 ֱ�Ӷ���
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

//�������޸� �����ǷǷ�ҳ ���Ƿ�ҳ �Լ�NEW_FLAGS��
#define NEW_FLAGS 'Mnew'
#define POOL_FLAG PagedPool

void* operator new(size_t size);
void* operator new[](size_t size);
void operator delete(void* ptr);
void operator delete[](void* ptr);