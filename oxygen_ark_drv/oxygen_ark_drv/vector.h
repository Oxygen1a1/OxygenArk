#pragma once
#include "base.hpp"
#include "allocator.h"
#include "log.hpp"


namespace krl_std{
	
	
	
	template <typename _T>
	class vector
	{
		//vector保存三个指针
		//strat end end_of_storge 方便快速计算

	private:
		_T* _Start;
		_T* _End;
		_T* _End_of_storage;
		allocator<_T> _Data_allocator;
		//模板所必须的 用于萃取(traits)
	public:
		
		typedef _T value_type;
		typedef value_type* pointer;
		typedef value_type* iterator;
		typedef _T& reference;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;//可以判断x64环境
	public:

		//虚构
		~vector() {

			if(this->_Start!=nullptr)
				this->destory_and_deallocate();
		}
		//构造函数
		vector() {

			this->_Start = this->_End = this->_End_of_storage = nullptr;
		}
		//需要T有默认构造
		vector(size_t n, _T val=_T()) {
			this->_Start = this->_End = this->_End_of_storage = nullptr;
			auto ptr = _Data_allocator.allocate(n+1,val);

			this->_Start = ptr;
			this->_End = this->_End_of_storage = (this->_Start + n);
		}

		vector(iterator first, iterator last) {
			this->_Start = this->_End = this->_End_of_storage = nullptr;

			if (first > last) {
				OLOG::LOG("iter err!", true);

				return;
			}

			auto alloc_count = last - first;

			
			//必须自带默认的构造
			auto ptr = _Data_allocator.allocate(alloc_count);
			if (ptr == nullptr) {

				OLOG::LOG("failed to alloc", true);


				__debugbreak();

				return;
			}

			for (auto i = 0l; i < alloc_count; i++) {

				__try {

					ptr[i] = first[i];

				}
				__except (1) {
					OLOG::LOG("iter err!", true);
					this->clear();

					return;
				}

			}

			_Start = ptr;
			_End = ptr + alloc_count;
			_End_of_storage = _End;
		}
		//拷贝构造
		vector(const vector<_T>& rhs) {

			assign(rhs);
		}

		//vector清除空间
		auto destory_and_deallocate() -> void {

			if(this->_Start!=nullptr)
				_Data_allocator.deallocate(this->_Start);

			this->_Start = this->_End = this->_End_of_storage = nullptr;
		}
		
		//reallocate 空间不够 重新加
		auto reallocate(size_t count = 0) -> void {
			//分情况 这个函数当size=0的时候,是用来增长倍数大小
		//获取当前size大小
			if (count == 0) {
				count = (_End_of_storage - _Start);
				auto now_count = _End - _Start;
				auto alloc_count = count == 0 ? 1 : count * 2;
				
				_T* ptr = _Data_allocator.allocate(alloc_count);
				if (ptr == 0) {

					OLOG::LOG("failed to alloc mem!", true);
					return;
				}

				//copy
				if (now_count != 0) memcpy(ptr, this->_Start, sizeof(_T) * (now_count));

				//free
				_Data_allocator.deallocate(this->_Start);

				this->_Start = ptr;

				//当前是0 也就是说空
				if (now_count == 0)
					this->_End =ptr;
				else this->_End = now_count + ptr;

				this->_End_of_storage = ptr + alloc_count;

			}
			else {
				//如果不为0 只有构造函数才会调用
				_T* ptr = _Data_allocator.allocate(count + 1);
				if (ptr == 0) {

					OLOG::LOG("failed to alloc mem!", true);
					return;
				}

				this->_Start = ptr;
				this->_End = ptr + count + 1;
				this->_End_of_storage = this->_End;
			}

		}

		//成员函数
		auto capacity() -> u32 const { return u32(_End_of_storage - _Start); };
		auto size() -> u32 const { return (u32)(_End - _Start); };
		auto front() -> _T& {
			if (_End == nullptr || _Start == nullptr) { reallocate(); }

			return *_Start;

		}
		auto back() -> _T& {

			if (_End == nullptr || _Start == nullptr) { reallocate(); }

			return *(_End - 1);
		}
		auto push_back(const _T& value) -> void {

	
			if (_End == nullptr || _Start == nullptr || _End == _End_of_storage) { reallocate(); }


			*_End = value;
			_End++;
		}
		auto pop_back() -> void {
			if (_End == nullptr || _Start == nullptr) { reallocate(); }

			if (_End == _Start) return;

			_End--;

		}
		auto clear() -> void {

			if (_End == nullptr || _Start == nullptr) { return; }
			this->destory_and_deallocate();
		}
		auto insert(iterator pos, const _T& value) -> void {

			//这个时候比较特殊
			if (_End == nullptr || _Start == nullptr) {
				
				//有默认拷贝构造函数
				auto ptr = new _T[2]{value,value};
				if (ptr == 0) return;

				this->_Start = ptr;
				this->_End = ptr + 1;
				this->_End_of_storage = ptr + 1;
			}

			if (pos == _End) {
				push_back(value);
			}
			else {
				//空间不够 这里一定要注意 先判断下这个指针到底位于第几个,不然可能会出现
				//地址移动,导致问题
				u32 pos_index = 0;
				if (pos >= _Start && pos < _End) {

					pos_index = (u32)(pos - _Start);

				}
				else { __debugbreak(); return; }//pos有误

				if (_End == _End_of_storage) {
					reallocate();

					//这个时候需要改变pos
					pos = _Start + pos_index;
				}

				

				for (auto iter = begin(); iter != end(); iter++) {

					if (iter != pos) continue;
					else {
						//找到了 从最后一个往后依次放
						for (auto cur_iter = _End; cur_iter != iter; cur_iter--) {

							*cur_iter = *(cur_iter - 1);
						}

						*pos = value;

						//最后指针往后移
						_End++;
						break;
					}

				}

			}
		}

		auto find(const _T& value) -> iterator {

			for (auto iter = begin(); iter != end(); iter++) {
				
				if (value == *iter) return iter;
				
			}

			return _End;
		}

		auto begin() -> iterator const { return _Start; }
		auto end() -> iterator const { return _End; }
		//重载operator
		bool operator ==(vector<_T>& comp) {

			//防止访问时出错
			__try {
				if (this->_End - this->_Start != comp._End - comp._Start) return false;

				//都是空的
				if (begin() == end()) return false;

				for (auto iter = begin(), c_iter = comp.begin(); iter != end(); iter++, c_iter++) {

					if (*iter == *c_iter) continue;
					else return false;
				}

				return true;
			}
			__except (1) {
				return false;
			}
		}
		bool operator !=(vector<_T>& comp) {

			//防止访问时出错
			__try {
				if (this->_End - this->_Start != comp._End - comp._Start) return false;

				//都是空的
				if (begin() == end()) return true;

				for (auto iter = begin(), c_iter = comp.begin(); iter != end(); iter++, c_iter++) {

					if (*iter == *c_iter) continue;
					else return true;
				}

				return false;
			}
			__except (1) {
				return true;
			}
		}
		void operator=(const vector<_T>& rhs) {
			//调用拷贝构造
			assign(rhs);
		}
		//重载[]
		_T& operator [] (int index) {
			if (index >= _End - _Start) {


			
#ifdef DBG
			//下标越界
			__debugbreak();
#endif
			OLOG::LOG("index overflow!\r\n",true);
				
			return *_End;
			}

			//
			return *(_Start + index);

		}
	private:
		//拷贝构造调用
		void assign(const vector<_T>& rhs) {

			if (&rhs != this) {
	
				//深拷贝

				auto use_count = rhs._End - rhs._Start;

				auto ptr = _Data_allocator.allocate(use_count+1);

				for (int i = 0; i < use_count; i++) {

					//需要有拷贝构造
					ptr[i] = rhs._Start[i];
				}


				this->_Start = ptr;
				this->_End = ptr+use_count;
				this->_End_of_storage = this->_End;
			}
		}
		
	};
	

}

