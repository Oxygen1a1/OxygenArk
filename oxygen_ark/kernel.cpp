#include "kernel.h"

namespace kernel {
	
	auto query_reg_from_currentversion(__in const char* queryKey,
		__out char* queryInfo)->bool {
		HKEY hKey;
		DWORD dwType, dwSize;
		char _queryInfo[32];
		bool ret = false;
		// 打开注册表键
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
			dwSize = sizeof(_queryInfo);

			// 查询 "ReleaseId" 值
			if (RegQueryValueExA(hKey, queryKey, NULL, &dwType, (LPBYTE)_queryInfo, &dwSize) == ERROR_SUCCESS && dwType == REG_SZ) {
				memcpy(queryInfo, _queryInfo, strlen(_queryInfo)+1);
				ret = true;
			}
			else {
				ret = false;
			}

			RegCloseKey(hKey);
		}
		else {
			ret = false;
		}

		return ret;
	}
	//获取KUSER_SHARED_dATA的地址
	auto query_k_user_shared_data() -> UINT_PTR {

		SYSTEM_BASIC_INFORMATION basicInfo;
		auto status=NtQuerySystemInformation(SystemBasicInformation, &basicInfo, sizeof SYSTEM_BASIC_INFORMATION,
			0);
		if (NT_SUCCESS(status)) {
			//获取MaxUserAddr
			return basicInfo.MaximumUserModeAddress - PAGE_SIZE + 1;
			
		}
		return 0;
	}

	auto query_product_name(char* name) -> bool {

		return query_reg_from_currentversion("ProductName", name);
	}

	auto query_nt_version(char* ntVersion) -> bool {

		return query_reg_from_currentversion("CurrentVersion", ntVersion);
	}

	auto query_root_path(char* rootPath) -> bool {

		return query_reg_from_currentversion("SystemRoot", rootPath);
	}

	auto query_half_year_version(char* version) -> bool {
		
		return query_reg_from_currentversion("DisplayVersion", version);
	}


	auto query_system_info(const psystem_baisc_info info) -> bool {

		SYSTEM_BASIC_INFORMATION basicInfo;
		auto status = NtQuerySystemInformation(SystemBasicInformation, &basicInfo, sizeof SYSTEM_BASIC_INFORMATION,
			0);

		if (NT_SUCCESS(status)) {
			RTL_OSVERSIONINFOW osVersion{0};
			if (NT_SUCCESS(RtlGetVersion(&osVersion))) {

				sprintf_s(info->buildNumber, "%d", osVersion.dwBuildNumber);
				sprintf_s(info->majorVersion, "Window %d", osVersion.dwMajorVersion);

				sprintf_s(info->kUserSharedData, "0x%p", query_k_user_shared_data());
				query_half_year_version(info->halfYearVersion);
				query_nt_version(info->ntVersion);
				query_product_name(info->productName);
				query_root_path(info->systemRoot);
				
				sprintf_s(info->processorNumber, "%d", basicInfo.NumberOfProcessors);
				sprintf_s(info->r3maxAddr, "0x%p", basicInfo.MaximumUserModeAddress);
				sprintf_s(info->r3minAddr, "0x%p", basicInfo.MinimumUserModeAddress);
				sprintf_s(info->pageSize, "0x%x bytes", basicInfo.PageSize);
				sprintf_s(info->paSize, "0x%llx bytes", basicInfo.PageSize * basicInfo.NumberOfPhysicalPages);

			}

		}
		return 0;

	}



}