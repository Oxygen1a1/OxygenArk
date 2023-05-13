
#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)

    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{


    ui->setupUi(this);
	this->setWindowIcon(get_icon(":/bug1.ico"));
	if (!drv_load::LoadDriver("oxygenArk", "oxygen_ark_drv.sys")) {

		QMessageBox::critical(this, "Error", "Failed to load driver.");
		
	}


    auto size=this->size();
    ui->tabWidget->setFixedSize(size);
    ui->tabWidget->clear();


	init_process_view();
	init_about_view();
	

}

MainWindow::~MainWindow()
{
	if (!drv_load::UnloadDriver("OxygenArk")) QMessageBox::critical(this, "error", "driver unload err");
    delete ui;
}

//给定进程路径 获取进程icon
auto  MainWindow::get_file_icon(const wchar_t* full_path)->QIcon {

	QString processPath = QString::fromWCharArray(full_path, MAX_PATH);
	QFileIconProvider iconProvider;
	QIcon icon = iconProvider.icon(QFileInfo(processPath));
	return icon;
}

//通过rcc文件 获取图片(用于显示)
auto MainWindow::get_pixmap(const char* name) -> QPixmap
{
	if (QResource::registerResource("res.rcc")) {
		qDebug() << "Resource file loaded successfully";
	}
	else {
		qDebug() << "Failed to load resource file";
	}

	
	QPixmap pixmap(name);

	QResource::unregisterResource("res.rcc");

	return pixmap;
}

auto MainWindow::update_process_view(const QList<process::p_info> list) -> void
{
	auto view = ui->processtreeView;
	static bool first = true;
	if (first) {
		this->processInfoModel= new QStandardItemModel();
		first = false;
	}

	if (processInfoModel != nullptr) {
		
		processInfoModel->clear();
	}

	int totoalCount=0, hideCount=0, systemCount=0;

	
	auto hLabel = new QStringList();
    hLabel->append("进程名称 ");
    hLabel->append("PID ");
	hLabel->append(("PPID "));
	hLabel->append(("用户层可访问 "));
	hLabel->append(("文件厂商 "));
	hLabel->append(("会话ID "));
	hLabel->append(("进程路径 "));
	hLabel->append(("启动时间   "));
	hLabel->append(("命令行 "));


	processInfoModel->setHorizontalHeaderLabels(*hLabel);
	
	int index = 0;
	for (auto item : list) {
		totoalCount++;
		if (!item.uaccess) systemCount++;
		QString pid = QString::number(item.pid);
		QStandardItem* pidItem = new QStandardItem(pid);
		processInfoModel->setItem(index, process::process_info_index::pid, pidItem);
		

		auto nameItem = new QStandardItem(item.name);
		processInfoModel->setItem(index, process::process_info_index::name, 
			nameItem);
		

		processInfoModel->setItem(index, process::process_info_index::stime,
			new QStandardItem(QString(item.stime.toString()))
		);

		QString sid = QString::number(item.sid);
		processInfoModel->setItem(index,process::process_info_index::sid,
			new QStandardItem(sid)
		);

		//full path
		char tmp[MAX_PATH] = { 0 };
		sprintf(tmp, "%S", item.fpath);
		processInfoModel->setItem(index, process::process_info_index::fpath,
			new QStandardItem(_C(tmp)));



		sprintf(tmp, "%S", process::get_file_companyname(item.fpath));
		processInfoModel->setItem(index, process::process_info_index::filecontractor,
			new QStandardItem(_C(tmp)));

		auto itemPid = processInfoModel->item(index, process::process_info_index::name);
		itemPid->setIcon(get_file_icon(item.fpath));

		processInfoModel->setItem(index, process::process_info_index::uaccess,
			new QStandardItem(item.uaccess ? ("--") : ("拒绝")));
		
		//cmd Line
		sprintf(tmp, "%S", item.cmdline);
		processInfoModel->setItem(index, process::process_info_index::cmdline,
			new QStandardItem(_C(tmp)));

		//PPID
		auto ppidStr=QString::number(item.ppid);
		processInfoModel->setItem(index, process::process_info_index::ppid,
			new QStandardItem(ppidStr));

		//设置不可写
		for (int i = 0; i < 9; i++) processInfoModel->item(index, i)->setFlags(
			processInfoModel->item(index, i)->flags() & ~Qt::ItemIsEditable);


		index++;

	}


	
	statusLabel.setText(QString("全部进程:%1 个 隐藏进程:%2 个 用户层不可访问:%3 个").
		arg(totoalCount).arg(hideCount).arg(systemCount));
	this->statusBar()->addWidget((QWidget*)&statusLabel);
	
	//用于排序
	static ProcessSortModel* proxyModel = new ProcessSortModel(this);
	proxyModel->setSourceModel(processInfoModel);

	view->header()->setSectionsMovable(false);
	view->header()->setSortIndicatorShown(true);
	view->setSortingEnabled(true);
	view->setModel(proxyModel);

	auto width=this->width();

}

auto MainWindow::init_process_view_menu() -> void
{

	QMenu* contextMenu = new QMenu(this);
	QMenu* detectSubMenu = new QMenu(_C("查看"), this);
	QMenu* injectMenu = new QMenu(_C("注入"), this);
	
	QAction* freshAction = new QAction(_C("刷新"), this);
	QAction* terminateAction = new QAction(_C("强制结束"), this);
	QAction* dumpAction = new QAction(_C("Dump"), this);
	QAction* nontraceRWAction = new QAction(_C("无痕读写"),this);
	QAction* hideAction= new QAction(_C("隐藏进程"), this);

	QAction* dThreadsAction = new QAction(_C("查看进程线程"), this);
	QAction* dHandlesAction = new QAction(_C("查看进程句柄表"), this);
	QAction* dTimerAction = new QAction(_C("查看进程定时器"), this);
	QAction* dWindowsAction = new QAction(_C("查看进程窗口"), this);
	QAction* dModulesAction = new QAction(_C("查看进程模块"), this);
	
	QAction* threadInjectAction = new QAction(_C("线程注入"), this);
	QAction* apcInjectAction = new QAction(_C("内核APC注入(不支持x86)"), this);
	QAction* icallInjectAction = new QAction(_C("回调注入(不支持x86)"), this);
	QAction* cowInjectAction = new QAction(_C("COW注入(不支持x86)"), this);


	contextMenu->addAction(freshAction);
	contextMenu->addAction(terminateAction);
	contextMenu->addAction(dumpAction);
	contextMenu->addAction(nontraceRWAction);
	contextMenu->addAction(hideAction);


	detectSubMenu->addAction(dThreadsAction);
	detectSubMenu->addAction(dHandlesAction);
	detectSubMenu->addAction(dTimerAction);
	detectSubMenu->addAction(dWindowsAction);
	detectSubMenu->addAction(dModulesAction);

	injectMenu->addAction(threadInjectAction);
	injectMenu->addAction(apcInjectAction);
	injectMenu->addAction(icallInjectAction);
	injectMenu->addAction(cowInjectAction);

	contextMenu->addMenu(detectSubMenu);
	contextMenu->addMenu(injectMenu);

	terminateAction->setIcon(get_icon(":/terminate.ico"));
	nontraceRWAction->setIcon(get_icon(":/rw.ico"));
	dThreadsAction->setIcon(get_icon(":/threads.ico"));
	dTimerAction->setIcon(get_icon(":/timer.ico"));
	dWindowsAction->setIcon(get_icon(":/windows.ico"));
	dModulesAction->setIcon(get_icon(":/modules.ico"));
	dHandlesAction->setIcon(get_icon(":/handles.ico"));


	ui->processtreeView->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(ui->processtreeView, &QTreeView::customContextMenuRequested, [=](const QPoint& pos) {

		contextMenu->exec(ui->processtreeView->viewport()->mapToGlobal(pos));
		});

	connect(terminateAction, &QAction::triggered, [=]() {
		

		process::force_terminate(get_sel_pid());

		});

	connect(freshAction, &QAction::triggered, [=]() {
		//创建新线程
		ProcessEnumThread* thread = new ProcessEnumThread(this);
		connect(thread, &ProcessEnumThread::processListReady, this, &MainWindow::onProcessListReady);
		thread->start();


		});
	
	connect(dumpAction, &QAction::triggered, [=]() {

		//开新线程解决
		QMessageBox::information(this, "info", "功能尚未完善");
		});
	connect(nontraceRWAction, &QAction::triggered, [=]() {

		//开新线程解决
		QMessageBox::information(this, "info", "功能尚未完善");
		});
	connect(hideAction, &QAction::triggered, [=]() {

		process::hide_process(get_sel_pid());

		});
	connect(dThreadsAction, &QAction::triggered, [=]() {

		show_threads_info();
		
		});
	connect(dHandlesAction, &QAction::triggered, [=]() {

		//枚举句柄表
		show_handles_info();
		});
	connect(dTimerAction, &QAction::triggered, [=]() {

		//枚举定时器
		show_timer_info();
		});
	connect(dWindowsAction, &QAction::triggered, [=]() {

		//枚举窗口
		show_windows_info();

		});
	connect(dModulesAction, &QAction::triggered, [=]() {

		//枚举模块
		show_modules_info();
		});
	connect(threadInjectAction, &QAction::triggered, [=]() {

		auto pid = get_sel_pid();
		
		auto file_name= QFileDialog::getOpenFileName(this,"请选择要注入的DLL", "/", "动态链接库 (*.dll)");
		//需要转换成windows的下一级目录\ 
		QString nativeFilename = QDir::toNativeSeparators(file_name);
		auto dllPath = new wchar_t[MAX_PATH];
		memset(dllPath, 0,sizeof(wchar_t)* MAX_PATH);

		nativeFilename.toWCharArray(dllPath);
		if (process::inject(pid, dllPath)) {

			QMessageBox::information(this, "success", "inject success!");
		}
		else {

			QMessageBox::critical(this, "error", "failed to inject!");
		}
		
		delete dllPath;
		});

	connect(apcInjectAction, &QAction::triggered, [=]() {

		QMessageBox::information(this, "info", "功能尚未完善");

		});
	connect(icallInjectAction, &QAction::triggered, [=]() {

		QMessageBox::information(this, "info", "功能尚未完善");

		});
	connect(cowInjectAction, &QAction::triggered, [=]() {



		});
}

auto MainWindow::get_icon(const char* iconname) -> QIcon
{
	if (QResource::registerResource("res.rcc")) {
		qDebug() << "Resource file loaded successfully";
	}
	else {
		qDebug() << "Failed to load resource file";
	}

	QIcon icon(iconname);

	QResource::unregisterResource("res.rcc");

	return icon;
}

auto MainWindow::update_os_info_view(QTableView* view) -> void
{


	static bool first = true;
	if (first) {

		osInfoModel = new QStandardItemModel();
		first = false;
	}
	else {

		osInfoModel->clear();
	}


	auto vHeads = new QStringList();
	vHeads->append(_C("操作系统版本:"));
	vHeads->append(_C("构建版本号: "));
	vHeads->append(_C("用户程序最低地址: "));
	vHeads->append(_C("用户程序最高地址: "));
	vHeads->append(_C("页面大小: "));
	vHeads->append(_C("处理器个数:"));
	vHeads->append(_C("物理内存大小: "));
	vHeads->append(_C("KUSER_SHARED_DATA: "));
	vHeads->append(_C("nt版本: "));
	vHeads->append(_C("系统根目录: "));
	vHeads->append(_C("电脑名称: "));
	vHeads->append(_C("发行编码: "));


	
	auto info=new kernel::system_baisc_info();
	kernel::query_system_info(info);

	auto rowItems = QList<QStandardItem*>();

	for (int i = 0; i < 12; i++) {
		auto itemHead = new QStandardItem(vHeads->at(i));
		this->osInfoModel->appendRow(itemHead);
	}
	
	for (int i = 0; i < 12; i++) {
		auto infoStr = QString(_C((CHAR*)(((UINT64)info) + MAX_PATH * i)));
		auto item = new QStandardItem(infoStr);
		osInfoModel->setItem(i, 1, item);
	}
	
	delete info;
	
	view->setModel(this->osInfoModel);
	view->verticalHeader()->setVisible(false);
	view->horizontalHeader()->setVisible(false);

	QString styleSheet =
		"QTableView {"
		"  background-color: white;" 
		"  alternate-background-color: lightgray;" 
		"  selection-background-color: blue;" 
		"  gridline-color: gray;" 
		"}"
		"QTableView::item {"
		"  color: black;" 
		"}";
	view->setStyleSheet(styleSheet);


	view->resizeColumnsToContents();
	view->setWordWrap(true);

	this->statusLabel.setText("");
	this->statusBar()->addWidget(&this->statusLabel);

}

auto MainWindow::init_process_view() -> void
{

	ui->tabWidget->addTab(ui->processtreeView, get_icon(":/modules.ico"), _C("进程 "));
	ui->processtreeView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
	ui->processtreeView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	ui->processtreeView->setHorizontalScrollBar(new QScrollBar());

	ProcessEnumThread* thread = new ProcessEnumThread(this);
	connect(thread, &ProcessEnumThread::processListReady, this, &MainWindow::onProcessListReady);
	thread->start();
	init_process_view_menu();
	//update_process_view(list);
	ui->processtreeView->update();
	
}

auto MainWindow::init_about_view() -> void
{

	QGridLayout* aboutLayout = new QGridLayout();
	QVBoxLayout* donateLayout = new QVBoxLayout();
	QWidget* container = new QWidget();
	QGroupBox* donateBox = new QGroupBox();
	QTextEdit* textInfo = new QTextEdit();


	textInfo->setReadOnly(true);
	textInfo->setFont(QFont("PingFang SC", 12));
	textInfo->setText(("免责声明：\r\n\
本AntiRootKit工具（以下简称“本工具”）仅适用于Windows平台。\r\n\
在使用本工具之前，请您仔细阅读并充分理解本免责声明的所有条款。\r\n\
一旦您开始使用本工具，即表示您已阅读并同意接受本免责声明中的所有条款和条件。\r\n\
如果您不同意本免责声明的任何内容，请立即停止使用本工具。\r\n\
  1.本工具仅供个人和企业用户在法律允许的范围内用于查杀恶意软件和保护计算机系统安全。严禁将本工具用于任何非法用途，包括但不限于破坏他人计算机系统、窃取他人信息等行为。\
如因使用本工具进行非法行为而产生的法律责任，由使用者自行承担。\r\n\
  2.尽管我已尽最大努力确保本工具的安全性和有效性，但不能保证本工具能在所有情况下完全查杀恶意软件或解决与RootKit相关的问题。因使用本工具可能造成的任何直接或间接损失，我概不负责。\r\n\
  3.本工具的开发者保留对本免责声明的最终解释权，并可随时对本免责声明进行修改。请您定期查看本免责声明以确保您对本工具的使用仍在符合本免责声明的规定。\r\n\
在此，我要特别感谢Pchunter和YdArk团队，他们的工作为本工具的设计提供了灵感和功能启发。\r\n\
同时，我也要感谢开源的winark和openark(功能参考)。\r\n\
如您在使用过程中遇到任何问题，请随时与我联系。"));




	donateBox->setTitle(_C("捐赠我 "));


	auto wxPixmap = new QLabel();

	wxPixmap->setPixmap(get_pixmap(":/wx.png"));


	donateLayout->addWidget(wxPixmap);

	aboutLayout->addWidget(ui->osInfoView, 0, 0);
	aboutLayout->addWidget(donateBox, 0, 1);
	aboutLayout->addWidget(textInfo, 0, 2);

	container->setLayout(aboutLayout);
	donateBox->setLayout(donateLayout);

	auto width = this->width();
	aboutLayout->setColumnMinimumWidth(0, width / 3);
	aboutLayout->setColumnMinimumWidth(1, width / 3);
	aboutLayout->setColumnMinimumWidth(2, width / 3);



    ui->tabWidget->addTab(container, get_icon(":/computer.ico"), _C("关于 "));
	update_os_info_view(ui->osInfoView);
}

auto MainWindow::show_modules_info() -> void
{
	//枚举模块信息
	static QStandardItemModel* model = new QStandardItemModel();
	static QTreeView* modulesView = new QTreeView();
	static QVBoxLayout* layout = new QVBoxLayout();
	static QWidget* widget = new QWidget();
	static bool first = true;

	if (first) first = false;
	else model->clear();
	
	auto pid = get_sel_pid();
	auto hLabels = QStringList();
	hLabels.append("模块路径");
	hLabels.append("起始地址");
	hLabels.append("结束地址");
	hLabels.append("文件厂商");

	layout->addWidget(modulesView);
	widget->setLayout(layout);
	model->setHorizontalHeaderLabels(hLabels);


	//枚举进程模块
	auto modulesInfo=process::enum_modules(pid);


	if (modulesInfo == nullptr) return;
	widget->setWindowTitle(QString("进程id:%1  模块个数:%2").arg((DWORD64)pid).arg(modulesInfo->moduleCount));
	
	for (int row = 0; row < modulesInfo->moduleCount; row++) {

		for (int clo = 0; clo < 4; clo++) {

			auto str = 
				QString((char*)(((UINT64)&modulesInfo->modules[row]) + MAX_PATH * clo));
			model->setItem(row, clo, 
				new QStandardItem(str));

		}


	}

	widget->setFixedSize({ 500,300 });
	modulesView->setModel(model);
	widget->show();

}

auto MainWindow::show_windows_info() -> void
{
	static auto container=new QWidget();
	static auto layout = new QVBoxLayout();
	static auto treeView = new QTreeView();
	static auto model = new QStandardItemModel();
	static bool first = true;

	if (first) {
		first = false;
	}
	else {
		model->clear();
	}

	QStringList hLabel;
	hLabel.append("窗口句柄");
	hLabel.append("窗口标题");
	hLabel.append("窗口是否可见");
	hLabel.append("所属进程ID");
	hLabel.append("所属线程ID");

	model->setHorizontalHeaderLabels(hLabel);

	auto windowsInfo = process::enum_windows(get_sel_pid());
	if (windowsInfo == nullptr) return;
	
	for (int row = 0; row < windowsInfo->count; row++) {
		auto info = windowsInfo->infos[row];
		//开始设置
		model->setItem(row, 0, new QStandardItem(QString::number((ULONG64)info.hwnd, 16)));
		model->setItem(row, 1, new QStandardItem(_C(info.titile)));
		model->setItem(row, 2, new QStandardItem(info.isVisible?QString("是") :QString("否")));
		model->setItem(row, 3, new QStandardItem(QString("%1").arg((ULONG64)info.pid)));
		model->setItem(row, 4, new QStandardItem(QString("%1").arg((ULONG64)info.tid)));

	}


	container->setFixedSize({ 697,507 });
	container->setWindowTitle(QString("窗口总数 %1").arg(windowsInfo->count));
	container->setLayout(layout);
	layout->addWidget(treeView);
	treeView->setModel(model);
	delete[] windowsInfo;
	container->show();
}

auto MainWindow::show_timer_info() -> void
{

	static auto container = new QWidget();
	static auto layout = new QVBoxLayout();
	static auto treeView = new QTreeView();
	static auto model = new QStandardItemModel();
	static bool first = true;

	if (first) {
		first = false;
	}
	else {
		model->clear();
	}

	QStringList hLabel;
	hLabel.append("定时器对象");
	hLabel.append("回调函数");
	hLabel.append("时间间隔");
	hLabel.append("所属模块");

	model->setHorizontalHeaderLabels(hLabel);
	
	auto timerInfo = process::enum_timers(get_sel_pid());


	if (timerInfo == nullptr) return;

	for (int row = 0; row < timerInfo->count; row++) {
		auto info = timerInfo->infos[row];
		//开始设置
		model->setItem(row, 0, new QStandardItem(QString::number((ULONG64)info.timer_object, 16)));
		model->setItem(row, 1, new QStandardItem(QString::number((ULONG64)info.pfn, 16)));
		model->setItem(row, 2, new QStandardItem(QString::number((ULONG64)info.elapse, 16)));
		model->setItem(row, 3, new QStandardItem(QString(info.modules)));
	}


	container->setFixedSize({ 480,300 });
	container->setWindowTitle(QString("定时器总数 %1").arg(timerInfo->count));
	container->setLayout(layout);
	layout->addWidget(treeView);
	treeView->setModel(model);
	container->show();


	delete timerInfo->infos;
	delete timerInfo;//清理内存

}

auto MainWindow::show_handles_info() -> void
{
	static auto container = new QWidget();
	static auto layout = new QVBoxLayout();
	static auto treeView = new QTreeView();
	static auto model = new QStandardItemModel();
	static bool first = true;

	if (first) {
		first = false;
	}
	else {
		model->clear();
	}

	QStringList hLabel;
	hLabel.append("句柄值");
	hLabel.append("句柄权限");
	hLabel.append("句柄类型");
	hLabel.append("句柄对象");
	hLabel.append("句柄引用");
	hLabel.append("指针引用");
	hLabel.append("句柄名称");
	hLabel.append("关闭保护");

	model->setHorizontalHeaderLabels(hLabel);

	auto handlesInfo = process::enum_handles(get_sel_pid());
	if (handlesInfo == nullptr) return;

	for (int row = 0; row < handlesInfo->count; row++) {
		auto info = handlesInfo->infos[row];
		//开始设置
		model->setItem(row, 0, new QStandardItem(QString::number((ULONG64)info.handle, 16)));
		model->setItem(row, 1, new QStandardItem(QString::number((ULONG64)info.access, 16)));
		model->setItem(row, 2, new QStandardItem(QString(info.handleType)));
		model->setItem(row, 3, new QStandardItem(QString::number((ULONG64)info.handleObject, 16)));
		model->setItem(row, 4, new QStandardItem(QString::number((ULONG64)info.handleRef, 10)));
		model->setItem(row, 5, new QStandardItem(QString::number((ULONG64)info.ptrRef, 10)));
		model->setItem(row, 6, new QStandardItem(QString(info.handleName)));
		model->setItem(row, 7, new QStandardItem(info.closeProtect ?QString("是") : QString("否")));

	}

	container->setFixedSize({ 697,507 });
	container->setWindowTitle(QString("句柄总数 %1").arg(handlesInfo->count));
	container->setLayout(layout);
	layout->addWidget(treeView);
	treeView->setModel(model);
	delete[] handlesInfo->infos;
	delete[] handlesInfo;
	container->show();

}


auto MainWindow::show_threads_info()->void {

	
		//记得清理内存
		static auto container = new QWidget();
		static auto treeView = new QTreeView();
		static auto layout = new QVBoxLayout();
		static auto model = new QStandardItemModel();
		static auto hLabels = new QList<QString>();
		static bool first = true;
		if (first) first = false;
		else model->clear();//清理内存

		hLabels->append("线程ID");
		hLabels->append("StartAddress");
		hLabels->append("线程优先级");
		hLabels->append("ETHREAD");
		hLabels->append("TEB");
		hLabels->append("切换次数");
		hLabels->append("线程起始地址所在模块");//如果线程不在这个地方,属于可疑线程
		model->setHorizontalHeaderLabels(*hLabels);

		

		auto threadsInfo = process::query_threads_by_pid(get_sel_pid());

		if (threadsInfo == nullptr) return;

		for (int row = 0; row < threadsInfo->threadsCount; row++) {

			for (int col = 0; col < 7; col++) {
				auto str = (PCHAR)(&threadsInfo->info[row]) + MAX_PATH * col;
				model->setItem(row, col,
					new QStandardItem(QString(str)));
			}
		}

		layout->addWidget(treeView);
		container->setLayout(layout);
		treeView->setModel(model);



		container->setWindowTitle(QString("线程总数 :%1").arg(threadsInfo->threadsCount));
		container->setFixedSize({ 500,300 });


		//清理内存
		delete[] threadsInfo->info;
		delete[] threadsInfo;

		container->show();
	
}
//因为中间多了个代理SortModel 所以需要先映射
auto MainWindow::get_sel_pid() -> HANDLE
{

	auto index = ui->processtreeView->currentIndex();
	auto sortModel = (ProcessSortModel*)ui->processtreeView->model();
	auto model = (QStandardItemModel*)sortModel->sourceModel();
	auto sourceIndex = sortModel->mapToSource(index);
	//一定要把sortModel 的 index映射一下
	auto item = model->item(sourceIndex.row(), process::process_info_index::pid);
	
	return (HANDLE)(item->text()).toULongLong();

}

auto MainWindow::onProcessListReady(const QList<process::p_info>& list)->void {

	//更新GUI
	update_process_view(list);

}




