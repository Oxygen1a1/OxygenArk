#pragma once
#include "base.hpp"
#include "allocator.h"
#include "log.hpp"

namespace krl_std {

	class string {
	public:
		//ctor
		string() {

			_Str = _Data_allocator.allocate(1);
			_Str[0] = 0;
			_Len = 0;
		}

		string(const string& str) {


			//深浅拷贝问题
			auto _len = str.length();
			//size=length+1(char)
			auto new_p = _Data_allocator.allocate(_len+1);

			//拷贝
			__try {

				memcpy(new_p, str.c_str(), _len + 1);
				_Str = new_p;
				this->_Len = _len;
			}
			__except (1) {
				//出错
#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);

			}
		}
	
		string(const char* s) {

			__try {

				auto _len = strlen(s);
				auto ptr = _Data_allocator.allocate(_len+1);
				memcpy(ptr, s, _len + 1);
				this->_Str = ptr;
				this->_Len = _len;

			}
			__except (1) {

#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);

			}
		}

		string(size_t n, char c) {

			__try {

				auto ptr = _Data_allocator.allocate(n + 1);

				memset(ptr, c, n);
				ptr[n] = 0;
				this->_Str = ptr;
				this->_Len = n;

			}
			__except (1) {

#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);

			}
		}
		
		//dtor
		~string() {

			this->_Data_allocator.deallocate(_Str);
		}


		//重载运算符
		auto operator==(string& str)->bool {

			auto _len = str.length();

			if (_len != this->_Len) return false;

			for (auto i = 0ul; i < _len; i++) {

				if (str[i] != (*this)[i]) return false;
			}

			return true;
		}

		auto operator==(const char* s)->bool {
			auto _len = strlen(s);

			if (_len != this->_Len) return false;

			for (auto i = 0ul; i < _len; i++) {

				if (s[i] != (*this)[i]) return false;
			}

			return true;


		}

		auto operator!=(const char* s)->bool {
			auto _len = strlen(s);

			if (_len != this->_Len) return true;

			for (auto i = 0ul; i < _len; i++) {

				if (s[i] != (*this)[i]) return true;
			}

			return false;

		}

		auto operator!=(string str)->bool {

			auto _len = str.length();

			if (_len != this->_Len) return true;

			for (auto i = 0ul; i < _len; i++) {

				if (str[i] != (*this)[i]) return true;
			}

			return false;

		}
		auto operator+(const string& str) ->string{
			string s_tmp;
			auto _len = str.length();

			auto new_len = _len + _Len;
			auto new_p = _Data_allocator.allocate(new_len + 1);

			__try {

				strcpy(new_p, _Str);
				strcat(new_p, str.c_str());
			}
			__except (1) {

#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);
				return nullptr;

			}

			s_tmp._Str = new_p;
			s_tmp._Len = new_len;
			return s_tmp;
		}


		auto operator+=(const string& str)->string& {
			auto _len = str.length();

			auto new_len = _len + _Len;
			auto new_p = _Data_allocator.allocate(new_len + 1);
			new_p[0] = 0;

			__try {

				strcpy(new_p, _Str);
				strcat(new_p, str.c_str());

				auto tmp_p = _Str;
				_Data_allocator.deallocate(tmp_p);
				_Str = new_p;
				_Len = new_len;
			}
			__except (1) {

#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);
				
			}
			return *this;
		}
		auto operator[](int index)->char& {

			if (index >= length()) {
#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("index err!\r\n", true);

				return _Str[length()-1];
			}

			return _Str[index];
		}

		//拷贝复制
		auto operator =(const string& str)->void {
			if (&str == this) return;

			//深浅拷贝问题
			auto _len = str.length();
			//size=length+1(char)
			auto new_p = _Data_allocator.allocate(_len + 1);

			//拷贝
			__try {

				memcpy(new_p, str.c_str(), _len + 1);
				//释放原有的
				_Data_allocator.deallocate(_Str);
				_Str = new_p;
				this->_Len = _len;
			}
			__except (1) {
				//出错
#ifdef DBG
				__debugbreak();
#endif // DEBUG
				OLOG::LOG("copy err!\r\n", true);

			}

		}
		//成员函数
		auto length()const ->  size_t  {return _Len;}

		auto c_str() const -> char*  { return _Str; }

		auto find(const char* str)->size_t {
			
			size_t sub_len = strlen(str);
			if (sub_len == _Len) {
				//特殊情况判断
				if (*this ==str) return 0;
				else return _Len + 1;//end of str
			}
			if (sub_len > _Len) return _Len + 1;

			for (auto i = 0ull; i < _Len; i++) {

				if (RtlCompareMemory(_Str + i, str, sub_len) == sub_len) {

					return i;
				}
			}

			return _Len + 1;//not find

		}

		auto find(string& str) -> size_t {
		
		
			auto sub_str = str._Str;
			auto sub_len = str._Len;
			if (sub_len == _Len) {
				//特殊情况判断
				if (str == *this) return 0;
				else return _Len + 1;//end of str
			}
			if (sub_len > _Len) return _Len + 1;

			for (auto i = 0ull; i < _Len; i++) {

				if (RtlCompareMemory(_Str+i, sub_str, sub_len) == sub_len) {

					return i;
				}
			}

			return _Len + 1;//not find

		}

		auto substr(size_t pos1,size_t pos2) ->string{
			
			string tmp;
			if ((pos1 > pos2) || (pos2 >= _Len)) return tmp;
		
			auto sub_len = pos2 - pos1 + 1;

			auto sub_p = _Data_allocator.allocate(sub_len+1);
			_Data_allocator.deallocate(tmp.c_str());
			__try {
				memcpy(sub_p, _Str + pos1, sub_len);

				tmp._Str = sub_p;
				tmp._Len = sub_len;
				sub_p[sub_len] = 0;

			}
			__except (1) {
#ifdef DBG
				__debugbreak();
#endif

				OLOG::LOG("failed to copy!", true);

			}
			return tmp;
		}

	private:
		char* _Str;
		size_t _Len;
		//分配器
		allocator<char> _Data_allocator;
	};


}