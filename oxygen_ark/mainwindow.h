#if _MSC_VER >= 1600
#pragma execution_character_set("utf-8")// ��ָ���֧��VS����
#endif

#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include "resource.h"
#include <QMainWindow>
#include <QMessageBox>
#include <QPushButton>
#include <QStringListModel>
#include <QStandardItemModel>
#include "enmu_process.h"
#include <QTreeView>
#include <QFileIconProvider>
#include "DriverLoad.h"
#include <QErrorMessage>
#include <psapi.h>
#include "ProcessSortModel.h"
#include <QScrollBar>
#include <QLabel>
#include <QResource>
#include <QVBoxLayout>
#include <QTableView>
#include <QListView>
#include <QGroupBox>
#include <QLayout>
#include <QTextEdit>
#include <QThread>
#include <QFileDialog>
#include "kernel.h"
#include "ProcessEnumThread.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

#define _C(x) QString::fromUtf8(x)





class MainWindow : public QMainWindow

{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    //Worker����
    auto show_threads_info() -> void;
    auto update_process_view(const QList<process::p_info> list) -> void;
    QStandardItemModel* processInfoModel;
    auto get_file_icon(const wchar_t* full_path) -> QIcon;
private:
    Ui::MainWindow *ui;
    HANDLE hDevice;//�����豸����
    QLabel statusLabel;
    //model����

    QStandardItemModel* osInfoModel;
    //ö�ٽ��� ������QtreeView��
  
    auto get_pixmap(const char* full_path) -> QPixmap;
   
    //��ʼ�������Ǹ��ط����Ҽ��˵�
    auto init_process_view_menu() -> void;
    auto get_icon(const char* iconname) -> QIcon;
    auto update_os_info_view(QTableView* view) -> void;

    auto init_process_view() -> void;
    auto init_about_view() -> void;
    auto get_sel_pid() -> HANDLE;
    //��ʾģ����Ϣ
    auto show_modules_info() -> void;
    auto show_windows_info() -> void;
    auto show_timer_info() -> void;
    auto show_handles_info() -> void;
    friend class ProcessEnumThread;
    //�ۺ���
public slots:
    void onProcessListReady(const QList<process::p_info>& list);

    
};

#endif // MAINWINDOW_H
