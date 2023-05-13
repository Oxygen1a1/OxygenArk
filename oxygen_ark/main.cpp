
#include "mainwindow.h"

#include <QApplication>


int main(int argc, char *argv[])
{

    QApplication a(argc, argv);
    MainWindow w;
	w.setWindowTitle("OxygenArk ver0.1");
    w.setMinimumSize({ 1100,700 });
    
    w.show();

    w.resize({ 1100,740 });
    w.setFixedSize({ 1100,740 });
    return a.exec();
}
