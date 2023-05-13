#include "R3.h"
//与R3通信的功能块


namespace R3{
	NTSTATUS dispatch_func_device_io(PDEVICE_OBJECT devcie_object, PIRP irp) {


		UNREFERENCED_PARAMETER(devcie_object);

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		auto stack = IoGetCurrentIrpStackLocation(irp);
		switch (stack->Parameters.DeviceIoControl.IoControlCode)
		{
		case CTL_QUERY_PROCESS: {
			
			auto buffer = (kprocess::pp_info)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS process{ nullptr };
			status=PsLookupProcessByProcessId((HANDLE)buffer->pid, &process);
			
			if (NT_SUCCESS(status)) {
				ObDereferenceObject(process);

				bool ret=kprocess::query_process_info(buffer, process);

				status = ret ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			}
			else break;
			
			irp->IoStatus.Information = sizeof(kprocess::p_info);
			irp->IoStatus.Status = status;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;


		}
		case CTL_QUERY_THREAD: {

			auto buf = (kprocess::pthreads_info_t)irp->AssociatedIrp.SystemBuffer;
			//验证地址
			status = kprocess::query_threads_info(buf);
			irp->IoStatus.Information = sizeof(kprocess::pthreads_info_t);
			irp->IoStatus.Status = status;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;


		}
		case CTL_TERMINATE_PROCESS: {
			auto b = kprocess::terminate_process(*(PHANDLE)irp->AssociatedIrp.SystemBuffer);
			if (NT_SUCCESS(b)) status = STATUS_SUCCESS;
			else status = STATUS_UNSUCCESSFUL;
			break;

		}
		case CTL_HIDE_PROCESS: {
			auto b = kprocess::hide_process(*(PHANDLE)irp->AssociatedIrp.SystemBuffer);
			if (b) status = STATUS_SUCCESS;
			else status = STATUS_UNSUCCESSFUL;
			break;
		}
		case CTL_QUERY_MODULES: {
			//枚举模块信息
			//这个时候默认从R3来的已经分配了内存
			auto buf = (Module::pmodules_info_t)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS process{ 0 };

			status = PsLookupProcessByProcessId(buf->pid, &process);
			if (!NT_SUCCESS(status)) {

				status = STATUS_UNSUCCESSFUL;
				break;
			}
			ObDereferenceObject(process);

			//判断一下是否够用
			if (Module::query_process_module_count(process) != buf->moduleCount) {

				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			//够用
			Module::enum_process_modules(process,buf);

			irp->IoStatus.Information = sizeof(Module::modules_info_t);
			irp->IoStatus.Status = status;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;

		}
		case CTL_QUERY_MODULES_COUNT: {
		
			PEPROCESS process{ 0 };
			auto buf = (PHANDLE)irp->AssociatedIrp.SystemBuffer;
			//询问模块个数
			status = PsLookupProcessByProcessId(*buf, &process);
			if (!NT_SUCCESS(status)) {
				break;
			}
			ObDereferenceObject(process);

			auto count = Module::query_process_module_count(process);
			*((PUINT64)buf) = count;

			irp->IoStatus.Information = sizeof(UINT64);
			irp->IoStatus.Status = status;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;

		}
		case CTL_QUERY_TIMERS_COUNT: {

			auto buf = (PHANDLE)irp->AssociatedIrp.SystemBuffer;

			auto count = windows::query_timer_count(*buf);
			auto retBuf = (unsigned int*)irp->AssociatedIrp.SystemBuffer;
			*retBuf = count;
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(int);
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
		case CTL_QUERY_TIMERS:{
			auto buf = (windows::pquery_timers_t)irp->AssociatedIrp.SystemBuffer;
			auto timersInfo = buf->timers_info->infos;
			LIST_ENTRY head = { 0 };
			InitializeListHead(&head);

			windows::query_process_timer((windows::pfind_list_t)&head, buf->pid);

			__try {

			
				int index = 0;
				for (auto entry = head.Flink; entry != &head; entry = entry->Flink) {

					auto item = CONTAINING_RECORD(entry, windows::find_list_t, list);

					timersInfo[index].elapse=item->timer->elapse;
					timersInfo[index].pfn = item->timer->pfn;
					timersInfo[index].timer_object = item->timer;
					Module::get_file_module_name(buf->pid, 
						(UINT_PTR)item->timer->pfn,timersInfo[index].modules);

					index++;

				}
			}
			__except (1) {

				//用户传入的有问题
				break;
			}
			//清空

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
			
		}
		case CTL_QUERY_HANDLES_COUNT: {


			auto buf = (PHANDLE)irp->AssociatedIrp.SystemBuffer;

			auto count = kprocess::query_process_handle_count(*buf);

			*((unsigned int*)(buf)) = count;

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(int);
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;

		}
		case CTL_QUERY_HANDLES: {
			auto buf = (kprocess::pquery_handle_t)irp->AssociatedIrp.SystemBuffer;

			auto ret = kprocess::query_process_handles(buf->pid, buf->infos);
			if (ret) {
				irp->IoStatus.Status = STATUS_SUCCESS;
				irp->IoStatus.Information = sizeof(kprocess::query_handle_t);
				IoCompleteRequest(irp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;

			}
			else break;

		}
		case CTL_INJECT: {

			auto buf = (inject::pinject_t)irp->AssociatedIrp.SystemBuffer;
			auto ret = false;
			PEPROCESS process{ 0 };

			if (!NT_SUCCESS(PsLookupProcessByProcessId(buf->pid, &process))) {
				break;
			}
			ObDereferenceObject(process);

			if (undoc::PsGetProcessWow64Process(process) != nullptr) {
				//x86注入
				ret = inject::inject_x86(process, &buf->dllPath[0]);
			}
			else {
				//x84注入
				ret = inject::inject_x64(process, &buf->dllPath[0]);
			}

			if (!ret) break;

			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;

		}
		default:
			break;
		}

		

		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	NTSTATUS dispatch_func_create_close(PDEVICE_OBJECT devcie_object, PIRP irp) {

		UNREFERENCED_PARAMETER(devcie_object);

		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return 0;
	}

	NTSTATUS dispatch_func_shutdown(PDEVICE_OBJECT dev, PIRP irp) {

		UNREFERENCED_PARAMETER(dev);
		UNREFERENCED_PARAMETER(irp);
		return STATUS_SUCCESS;
	}

	NTSTATUS init_device_and_symbolic(PDRIVER_OBJECT driver_object) {

		PDEVICE_OBJECT deoj{ 0 };
		NTSTATUS status = STATUS_SUCCESS;


		//可以使用Break 跳出循环
		while (1) {

			status = IoCreateDevice(driver_object, 0, &g_usDeviceName, FILE_DEVICE_UNKNOWN, 0, 0, &deoj);

			if (!NT_SUCCESS(status)) {

				DbgPrintEx(77, 0, "[+]failed to create device\r\n");

				break;
			}

			status = IoCreateSymbolicLink(&g_usSymbolicName, &g_usDeviceName);

			if (!NT_SUCCESS(status)) {

				DbgPrintEx(77, 0, "[+]failed to create symbolic link\r\n");

				IoDeleteDevice(deoj);

				break;
			}

			break;
		}

		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_func_create_close;

		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_func_device_io;

		driver_object->MajorFunction[IRP_MJ_SHUTDOWN] = dispatch_func_shutdown;
		
		return status;
	}

	void delete_device_and_symbolic(PDRIVER_OBJECT driver_object) {

		IoDeleteDevice(driver_object->DeviceObject);
		IoDeleteSymbolicLink(&g_usSymbolicName);

	}

}

