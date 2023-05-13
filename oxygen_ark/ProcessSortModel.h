#pragma once
#include <QSortFilterProxyModel>
#include "enmu_process.h"


//���ڰ�TreeView��model����������� �������� ��ȻPID PPID��������

class ProcessSortModel : public QSortFilterProxyModel {
public:
	ProcessSortModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}

	//����lessThan
	bool lessThan(const QModelIndex& left, const QModelIndex& right) const override {
		QVariant leftData = sourceModel()->data(left);
		QVariant rightData = sourceModel()->data(right);

		//��������Ҫ����ת������ֵ���бȽ�
		if (left.column() == process::process_info_index::pid || 
			left.column()==process::process_info_index::ppid) {
			bool leftOk, rightOk;
			int leftValue = leftData.toInt(&leftOk);
			int rightValue = rightData.toInt(&rightOk);

			if (leftOk && rightOk) {
				return leftValue < rightValue;
			}
		}

		// Fall back to string comparison if we didn't compare the PID column
		return QSortFilterProxyModel::lessThan(left, right);
	}
};