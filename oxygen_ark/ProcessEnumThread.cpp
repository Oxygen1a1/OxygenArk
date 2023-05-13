#include "ProcessEnumThread.h"


void ProcessEnumThread::run()
{
	QList<process::p_info> list;
	list.clear();
	process::enmu_process(list);

	emit processListReady(list);
}