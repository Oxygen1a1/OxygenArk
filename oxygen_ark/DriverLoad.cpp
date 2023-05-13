
#include"DriverLoad.h"
#include <winsvc.h>


HANDLE ghDevice;

namespace drv_load {



	BOOL LoadDriver(const  char* lpszDriverName, const  char* sysFileName/*��Driver.sys*/)
	{
		char szDriverImagePath[MAX_PATH] = { 0 };//���ڱ��� .sys��ȫ·����
		//�õ�����������·��
		GetFullPathNameA(sysFileName, 256, szDriverImagePath, NULL);
		//OutputDebugStringA("yjx:LoadDriver()");
		char buf[2048] = { 0 };

		OutputDebugStringA(buf);

		BOOL bRet = FALSE;

		SC_HANDLE hServiceMgr = NULL;//SCM�������ľ�� ������������
		SC_HANDLE hServiceDDK = NULL;//NT��������ķ�����

		hServiceMgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS); //SC_MANAGER_CREATE_SERVICE

		OutputDebugStringA(buf);

		//������������Ӧ�ķ���
		hServiceDDK = CreateServiceA(hServiceMgr,
			lpszDriverName, //�����������ע����е�����  
			lpszDriverName, // ע������������ DisplayName ֵ  
			SERVICE_START, // ������������ķ���Ȩ��  SERVICE_START ���� SERVICE_ALL_ACCESS
			SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������  
			SERVICE_DEMAND_START, // ע������������ Start ֵ   //ָ�������̵���StartService����ʱ�ɷ�����ƹ����������ķ���
			SERVICE_ERROR_NORMAL,//SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ  
			szDriverImagePath, // GetFullPathNameA szDriverImagePath ע������������·�� ��: C:\\222\1.sys
			NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
			NULL,
			NULL,
			NULL,
			NULL);

		OutputDebugStringA(buf);
		if (GetLastError() == ERROR_SERVICE_EXISTS) //ERROR_SERVICE_EXISTS 1073 //�����Ѿ�����
		{
			hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_START);////���� SERVICE_ALL_ACCESS //


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
		SC_HANDLE hServiceMgr = NULL;//SCM�������ľ��
		SC_HANDLE hServiceDDK = NULL;//NT��������ķ�����
		SERVICE_STATUS SvrSta;
		char buf[2048] = { 0 };
		//�򿪻�ȡ������ƹ�������� 
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
		//����������Ӧ�ķ���
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
		//��̬ж����������,ɾ������  
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



