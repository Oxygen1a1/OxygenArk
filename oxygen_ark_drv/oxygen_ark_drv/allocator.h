#pragma once
#include "base.hpp"
#include "log.hpp"
template<typename T>
class allocator
{
	const u32 tags = 'allo';
public:
	//Ä¬ÈÏ¿½±´¹¹Ôì
	auto allocate(size_t count,T val=T()) -> T* {

		auto ptr = new T[count];

		if (ptr == 0) {

			OLOG::LOG("allocator fails to alloc memory!\r\n", true);
			return nullptr;
		}
		
		for (int i = 0; i < count; i++) {
			ptr[i] = val;
		}

		return ptr;
	}
	auto deallocate(T* ptr) -> void {

		if (MmIsAddressValid(ptr)) {

			__try {

				delete[] ptr;
				ptr = nullptr;
			}
			__except (1) {

				OLOG::LOG("allocator fails to free mem!\r\n", true);

			}

		}
	}
};


