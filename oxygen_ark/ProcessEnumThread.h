#pragma once
#include "mainwindow.h"

class ProcessEnumThread : public QThread
{
	Q_OBJECT

public:
	explicit ProcessEnumThread(QObject* parent = nullptr):_Parent(parent) {};

signals:
	void processListReady(const QList<process::p_info>& list);

protected:
	void run() override;
private:
	QObject* _Parent;
};

