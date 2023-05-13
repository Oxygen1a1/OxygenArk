#pragma once
#include "base.hpp"


namespace OLOG{

#define LOG(text,is_fault,...) __x();\
	::DbgPrintEx(0,0,"[Oxygen Ark]:");\
	::DbgPrintEx(0,0,text,__VA_ARGS__);\
	if(is_fault) ::DbgPrintEx(0,0,"function -> %s,line -> %d",__FUNCTION__,__LINE__)


	auto __x() -> void;
	
}