#include "base.hpp"
#include "vector.h"
#include "R3.h"
#include "hide_process.h"
#include "undoc_func.hpp"

using namespace undoc;
void unload(PDRIVER_OBJECT drv) {
	R3::delete_device_and_symbolic(drv);
	//ȥ��
	HIDE_PROCESS::uninstall();

}


EXTERN_C  auto DriverEntry(PDRIVER_OBJECT drv,PUNICODE_STRING) -> NTSTATUS {


	//��ʼ�����ؽ���
	HIDE_PROCESS::init();
	drv->DriverUnload = unload;
	return R3::init_device_and_symbolic(drv);
}