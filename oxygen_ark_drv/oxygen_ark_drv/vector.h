#pragma once
#include "base.hpp"
#include "allocator.h"
#include "log.hpp"


namespace krl_std{
	
	
	
	template <typename _T>
	class vector
	{
		//vector��������ָ��
		//strat end end_of_storge ������ټ���

	private:
		_T* _Start;
		_T* _End;
		_T* _End_of_storage;
		allocator<_T> _Data_allocator;
		//ģ��������� ������ȡ(traits)
	public:
		
		typedef _T value_type;
		typedef value_type* pointer;
		typedef value_type* iterator;
		typedef _T& reference;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;//�����ж�x64����
	public:

		//�鹹
		~vector() {

			if(this->_Start!=nullptr)
				this->destory_and_deallocate();
		}
		//���캯��
		vector() {

			this->_Start = this->_End = this->_End_of_storage = nullptr;
		}
		//��ҪT��Ĭ�Ϲ���
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

			
			//�����Դ�Ĭ�ϵĹ���
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
		//��������
		vector(const vector<_T>& rhs) {

			assign(rhs);
		}

		//vector����ռ�
		auto destory_and_deallocate() -> void {

			if(this->_Start!=nullptr)
				_Data_allocator.deallocate(this->_Start);

			this->_Start = this->_End = this->_End_of_storage = nullptr;
		}
		
		//reallocate �ռ䲻�� ���¼�
		auto reallocate(size_t count = 0) -> void {
			//����� ���������size=0��ʱ��,����������������С
		//��ȡ��ǰsize��С
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

				//��ǰ��0 Ҳ����˵��
				if (now_count == 0)
					this->_End =ptr;
				else this->_End = now_count + ptr;

				this->_End_of_storage = ptr + alloc_count;

			}
			else {
				//�����Ϊ0 ֻ�й��캯���Ż����
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

		//��Ա����
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

			//���ʱ��Ƚ�����
			if (_End == nullptr || _Start == nullptr) {
				
				//��Ĭ�Ͽ������캯��
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
				//�ռ䲻�� ����һ��Ҫע�� ���ж������ָ�뵽��λ�ڵڼ���,��Ȼ���ܻ����
				//��ַ�ƶ�,��������
				u32 pos_index = 0;
				if (pos >= _Start && pos < _End) {

					pos_index = (u32)(pos - _Start);

				}
				else { __debugbreak(); return; }//pos����

				if (_End == _End_of_storage) {
					reallocate();

					//���ʱ����Ҫ�ı�pos
					pos = _Start + pos_index;
				}

				

				for (auto iter = begin(); iter != end(); iter++) {

					if (iter != pos) continue;
					else {
						//�ҵ��� �����һ���������η�
						for (auto cur_iter = _End; cur_iter != iter; cur_iter--) {

							*cur_iter = *(cur_iter - 1);
						}

						*pos = value;

						//���ָ��������
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
		//����operator
		bool operator ==(vector<_T>& comp) {

			//��ֹ����ʱ����
			__try {
				if (this->_End - this->_Start != comp._End - comp._Start) return false;

				//���ǿյ�
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

			//��ֹ����ʱ����
			__try {
				if (this->_End - this->_Start != comp._End - comp._Start) return false;

				//���ǿյ�
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
			//���ÿ�������
			assign(rhs);
		}
		//����[]
		_T& operator [] (int index) {
			if (index >= _End - _Start) {


			
#ifdef DBG
			//�±�Խ��
			__debugbreak();
#endif
			OLOG::LOG("index overflow!\r\n",true);
				
			return *_End;
			}

			//
			return *(_Start + index);

		}
	private:
		//�����������
		void assign(const vector<_T>& rhs) {

			if (&rhs != this) {
	
				//���

				auto use_count = rhs._End - rhs._Start;

				auto ptr = _Data_allocator.allocate(use_count+1);

				for (int i = 0; i < use_count; i++) {

					//��Ҫ�п�������
					ptr[i] = rhs._Start[i];
				}


				this->_Start = ptr;
				this->_End = ptr+use_count;
				this->_End_of_storage = this->_End;
			}
		}
		
	};
	

}

