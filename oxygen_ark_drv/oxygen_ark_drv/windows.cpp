#include "windows.hpp"

namespace windows {

	typedef void* (*fnValidateHwnd)(HWND);

	//���������ʱ���Ƿ��Ѿ�����
	auto find(PLIST_ENTRY head,ptimer_t timer) ->bool{


		for (auto entry= head->Flink;entry!=head;entry=entry->Flink) {

			auto item = CONTAINING_RECORD(entry, find_list_t, list);

			if (item->timer == timer) return true;

		}

		return false;

	}
	//ֻ�ܸ���tid��
	auto query_timer_count(PLIST_ENTRY head,HANDLE tid) -> unsigned int {

		unsigned int count = 0;
		PETHREAD thread{ 0 };
		auto status = PsLookupThreadByThreadId(tid, &thread);
		if (!NT_SUCCESS(status)) {
			return 0;
		}
		ObDereferenceObject(thread);


		auto volatile gtmrListHead = (PLIST_ENTRY)
			_Utils::find_module_export(_Utils::find_module_base("win32kbase.sys"),
				"gtmrListHead"
			);
		if (gtmrListHead == nullptr) return 0;//�������hash����

		for (auto entry = gtmrListHead->Flink;
				entry != gtmrListHead; entry = entry->Flink) {

				auto item = CONTAINING_RECORD(entry, timer_t, list1);
				//����ط����Ʋ��ܽ����� ��ʱ��PageFault
				//ע�� ����Ķ�ʱ���п�������hwnd==0�� �������ж�threadInfo
				if ((*(PETHREAD*)(item->head.threadInfo)) == thread
					) {

					if (find(head, item)) {
						continue;
					}
					else {
						auto _item = (pfind_list_t)ExAllocatePoolWithTag(PagedPool, sizeof find_list_t,
							'list');
						if (item == nullptr) {

							ONLY_DEBUG_BREAK;
						}
						_item->timer = item;
						InsertHeadList(head, (PLIST_ENTRY)(_item));
						count++;
					}

				}

		}

		return count;

	}


	//����һ������ͷ ���������� ����Ľ��̵����ж�ʱ��
	auto query_process_timer(__inout pfind_list_t head,HANDLE pid) -> void {
	
		//��ѯ�ʽ��̵������߳�
		auto tidArry = kprocess::query_threads_tid(pid);
		if (tidArry == nullptr) return;

		
		for (int i=0;tidArry[i];i++) {

			query_timer_count((PLIST_ENTRY)head, tidArry[i]);

		}

		ExFreePool(tidArry);

		return;

	}
	auto query_timer_count(HANDLE pid) -> unsigned int {

		unsigned int count = 0;


		//ѯ�������߳�

		auto tidArry = kprocess::query_threads_tid(pid);
		if (tidArry == nullptr) return 0;
		
		LIST_ENTRY head = { 0 };
		InitializeListHead(&head);
		for (int i=0;tidArry[i];i++) {

			count+=query_timer_count(&head, tidArry[i]);

		}
		
		//�ͷ��ڴ�
		for (auto entry = (&head)->Flink; entry != &head; entry = entry->Flink) {

			auto item = CONTAINING_RECORD(entry, find_list_t, list);
			ExFreePool(item);
		}
	
		return count;

	}



}