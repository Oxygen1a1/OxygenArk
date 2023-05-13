#pragma once
#include <QSortFilterProxyModel>
#include "enmu_process.h"


//用于把TreeView的model放入这个里面 重载排序 不然PID PPID排序会出错

class ProcessSortModel : public QSortFilterProxyModel {
public:
	ProcessSortModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}

	//重载lessThan
	bool lessThan(const QModelIndex& left, const QModelIndex& right) const override {
		QVariant leftData = sourceModel()->data(left);
		QVariant rightData = sourceModel()->data(right);

		//这两个需要把他转换成数值进行比较
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