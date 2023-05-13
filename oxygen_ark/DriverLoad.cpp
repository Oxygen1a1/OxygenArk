
#include"DriverLoad.h"
#include <winsvc.h>


HANDLE ghDevice;

namespace drv_load {



	BOOL LoadDriver(const  char* lpszDriverName, const  char* sysFileName/*如Driver.sys*/)
	{
		char szDriverImagePath[MAX_PATH] = { 0 };//用于保存 .sys的全路径名
		//得到完整的驱动路径
		GetFullPathNameA(sysFileName, 256, szDriverImagePath, NULL);
		//OutputDebugStringA("yjx:LoadDriver()");
		char buf[2048] = { 0 };

		OutputDebugStringA(buf);

		BOOL bRet = FALSE;

		SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄 服务管理器句柄
		SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

		hServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS); //SC_MANAGER_CREATE_SERVICE

		OutputDebugStringA(buf);

		//创建驱动所对应的服务
		hServiceDDK = CreateServiceA(hServiceMgr,
			lpszDriverName, //驱动程序的在注册表中的名字  
			lpszDriverName, // 注册表驱动程序的 DisplayName 值  
			SERVICE_START, // 加载驱动程序的访问权限  SERVICE_START 或者 SERVICE_ALL_ACCESS
			SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
			SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值   //指定当进程调用StartService函数时由服务控制管理器启动的服务。
			SERVICE_ERROR_NORMAL,//SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
			szDriverImagePath, // GetFullPathNameA szDriverImagePath 注册表驱动程序的路径 如: C:\\222\1.sys
			NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
			NULL,
			NULL,
			NULL,
			NULL);

		OutputDebugStringA(buf);
		if (GetLastError() == ERROR_SERVICE_EXISTS) //ERROR_SERVICE_EXISTS 1073 //服务已经存在
		{
			hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_START);////或者 SERVICE_ALL_ACCESS //


			OutputDebugStringA(buf);
		}

		bRet = StartServiceW(hServiceDDK, NULL, NULL);

		OutputDebugStringA(buf);
		if (hServiceDDK)
		{
			CloseServiceHandle(hServiceDDK);
		}
		if (hServiceMgr)
		{
			CloseServiceHandle(hServiceMgr);
		}

		return bRet;
	}

	bool io_ctl(ULONG ctl_code, void* inbuf, DWORD insize, void* outbuf, DWORD outsize) {

		static bool first = true;

		if (first) {

			ghDevice = CreateFileW(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
			if (ghDevice == 0 || ghDevice == INVALID_HANDLE_VALUE) {

				MessageBoxA(0, "FAILED TO CREATE FILE!", "ERROR", MB_OK | MB_ICONERROR);
				UnloadDriver("oxygenArk");
			}

			first = false;
		}


		return DeviceIoControl(ghDevice, ctl_code, inbuf, insize, outbuf, outsize, 0, 0);

	}


	BOOL UnloadDriver(const  char* lpszDriverName)
	{
		BOOL bRet = FALSE;
		SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
		SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
		SERVICE_STATUS SvrSta;
		char buf[2048] = { 0 };
		//打开获取服务控制管理器句柄 
		CloseHandle(ghDevice);
		hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (hServiceMgr == NULL)
		{

			OutputDebugStringA(buf);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{

			OutputDebugStringA(buf);
		}
		//打开驱动所对应的服务
		hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);

		if (hServiceDDK == NULL)
		{
			OutputDebugStringA(buf);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			//sprintf_s(buf, "OpenService() ok ! \n");
			OutputDebugStringA(buf);
		}

		if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
		{

			OutputDebugStringA(buf);
		}
		else
		{
			OutputDebugStringA(buf);
		}
		//动态卸载驱动程序,删除服务  
		if (!DeleteService(hServiceDDK))
		{
			OutputDebugStringA(buf);
		}
		else
		{
			OutputDebugStringA(buf);
		}
		bRet = TRUE;
	BeforeLeave:

		if (hServiceDDK)
		{
			CloseServiceHandle(hServiceDDK);
		}
		if (hServiceMgr)
		{
			CloseServiceHandle(hServiceMgr);
		}
		return bRet;
	}

	



}



