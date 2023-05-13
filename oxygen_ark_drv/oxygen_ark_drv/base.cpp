#include "base.hpp"
#include "log.hpp"
#pragma warning (disable : 4996)

void* operator new(size_t size) {

	return ExAllocatePoolWithTag(PagedPool, size, NEW_FLAGS);

}

void* operator new[](size_t size) {

	return ExAllocatePoolWithTag(PagedPool, size, NEW_FLAGS);
}

void operator delete(void* ptr) {

	__try {

		ExFreePool(ptr);
	}
	__except (1) {

		OLOG::LOG("delete err!\r\n", true);
	}
}

void operator delete[](void* ptr) {

	__try {

		ExFreePool(ptr);
	}
	__except (1) {

		OLOG::LOG("delete err!\r\n", true);
	}
}