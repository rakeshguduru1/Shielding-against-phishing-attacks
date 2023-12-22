import sys
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QPixmap
from PyQt5 import QtGui, QtCore,QtWidgets
from PyQt5.QtGui import QCursor
import sql_injection_scanner
import xss_scanner
import phish_feature_extractor
import rf_model


class Ui_Sql_detector(object):
        def setupUi(self,window):
            window.setObjectName("window")
            window.resize(521, 389)
            icon = QtGui.QIcon("bug.jpg")
            window.setWindowIcon(icon)
            #window.setWindowIcon(QIcon('bug.png'))

            self.centralwidget = QtWidgets.QWidget(window)
            self.centralwidget.setObjectName("centralwidget")

            self.icon = QLabel()

            # loading image
            self.pixmap = QPixmap('bug.png')

            # adding image to label
            self.icon.setPixmap(self.pixmap)

            # Optional, resize label to image size
            self.icon.resize(self.pixmap.width(),
                              self.pixmap.height())
            self.icon.setObjectName("icon")
            # show all the widgets
            #self.label.show()



            """check button code and its connectivity to button_click function"""
            self.check_button = QtWidgets.QPushButton(self.centralwidget)
            self.check_button.setGeometry(QtCore.QRect(210, 170, 93, 28))
            self.check_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
            self.check_button.setStyleSheet(
            "*{border: 2px solid '#16121';" +
            "border-radius: 75px;" +
            "font-size: 15px;" +
            "color: 'white';" +
            "padding: 15px 0;" +
            "margin: 100px 200px;}" +
            "*:hover{background: '#16121';}")
            self.check_button.setObjectName("check_button")
            self.check_button.clicked.connect(self.button_click)

            """url input section"""
            self.url_input = QtWidgets.QLineEdit(self.centralwidget)
            self.url_input.setGeometry(QtCore.QRect(70, 111, 431, 31))
            self.url_input.setStyleSheet(
            "border: 2px solid '#046e6e';" +
            "color: 'black';" + "font-size: 12px;" )
            self.url_input.setObjectName("url_input")

            self.label = QtWidgets.QLabel(self.centralwidget)
            self.label.setGeometry(QtCore.QRect(10, 111, 61, 31))
            self.label.setStyleSheet(
            "border: 2px solid '#046e6e';" +
            "color: 'black';" + "font-size: 12px;")
            self.label.setObjectName("label")

            """output message"""
            self.output_text = QtWidgets.QTextEdit(self.centralwidget)
            self.output_text.setGeometry(QtCore.QRect(30, 241, 461, 121))
            self.output_text.setStyleSheet(
            "border: 2px solid '#046e6e';" +
            "color: 'black';" + "font-size: 15px;")
            self.output_text.setObjectName("output_text")

            self.label_2 = QtWidgets.QLabel(self.centralwidget)
            self.label_2.setGeometry(QtCore.QRect(110, 10, 311, 41))
            self.label_2.setObjectName("label_2")

            window.setCentralWidget(self.centralwidget)
            self.statusbar = QtWidgets.QStatusBar(window)
            self.statusbar.setStyleSheet(
            #"border: 2px solid '#16121';" +
            "color: 'white';")
            self.statusbar.setObjectName("statusbar")
            window.setStatusBar(self.statusbar)

            self.retranslateUi(window)
            QtCore.QMetaObject.connectSlotsByName(window)

        def retranslateUi(self, window):
            _translate = QtCore.QCoreApplication.translate
            window.setWindowTitle(_translate("window", "Vulnerability Checker"))

            self.check_button.setText(_translate("window", "Check"))
            self.label.setText(_translate("window", "<html><head/><body><p><span style=\" font-size:50pt font:Robot;\"><b> URL :</span></p></body></html>"))
            self.label_2.setText(_translate("window", "<html><head/><body><p align=\"center\"><span style=\" font-size:16pt;\">Vulnerability Checker</span></p></body></html>"))


        def button_click(self):

            #passing URL as input
            url = self.url_input.text()

            #calling XSS scanner function
            xss_str= xss_scanner.scan_xss(url)

            #calling SQL Injection scanner functions
            sql_str = sql_injection_scanner.scan_sql_injection(url)

            #calling Phishing functions
            phish_obj = phish_feature_extractor.feature_extractor(url)
            phish_str = phish_obj.extract()

            #to view the output
            self.output_text.append("Testing URL: {}\n{}\n{}\n{}\n\n".format(url,phish_str,xss_str,sql_str))

if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    window = QtWidgets.QMainWindow()
    window.setStyleSheet("background: #41ccc3; ")

    ui = Ui_Sql_detector()
    ui.setupUi(window)
    window.show()
    sys.exit(app.exec())
