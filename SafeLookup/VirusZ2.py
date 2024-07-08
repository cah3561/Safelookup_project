import sys
import os
import hashlib
import requests
from datetime import datetime, timezone
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QMessageBox, QFileDialog,
    QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel
)
from PyQt5.QtCore import QSize

from PyQt5.QtGui import QIcon,QFont
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QLabel

def calculate_md5(filename):  # MD5 해시 계산 함수
    with open(filename, "rb") as f: 
        md5_hash = hashlib.md5()
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def delete_file(file_path):  # 파일 삭제 함수
    try:
        os.remove(file_path)  
        print(f"File {file_path} deleted successfully.")
    except FileNotFoundError:  
        print(f"File {file_path} not found.")
    except PermissionError:  
        print(f"No permission to delete file {file_path}.")
    except Exception as e:  
        print(f"An error occurred while deleting file {file_path}: {e}")

def generate_scan_report(file_path, md5_hash, result): # 스캔보고서 생성 함수
    scan_date_utc = datetime.strptime(result['scan_date'], "%Y-%m-%d %H:%M:%S")
    scan_date_local = scan_date_utc.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    report = f"File: {file_path}\nMD5 Hash: {md5_hash}\nDetection Ratio: {result['positives']}/{result['total']}\nScan Date (Local Time): {scan_date_local}\n\n"
    report += "Detected Engines:\n"
    for engine, result_str in result['scans'].items():
        report += f"{engine}: {result_str['result']}\n"
    return report

def scan_file(api_key, md5_hash): # 파일 스캔 함수
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': md5_hash}
    response = requests.get(url, params=params)
    return response.json()

# 메인 애플리케이션 클래스
class VirusTotalApp(QWidget):
    def __init__(self):
        super().__init__()
        self.api_key = 'fc4409575b69a4466c292c6a6b93a69bc8bb0cd421390b3ea10150938b8ff3cb'
        self.directory_path = 'C:/Users/Nicboy/Downloads'
        if not os.path.exists(self.directory_path):
            os.makedirs(self.directory_path)
        self.initUI()

    def initUI(self): # UI 초기화 함수
        self.setWindowTitle('Safe Lookup')
        self.setGeometry(100, 100, 600, 400)

        
        


        vbox = QVBoxLayout()

        # 이미지 추가
        self.image_label = QLabel(self)
        pixmap = QPixmap('D:/Nic/Safe Lookup/그림2.png').scaled(200,100)
        self.image_label.setPixmap(pixmap)
        self.image_label.setAlignment(Qt.AlignCenter)  
        vbox.addWidget(self.image_label)
     

        hbox = QHBoxLayout()
        
        # 파일 선택검사 버튼
        self.select_file_btn = QPushButton(self) 
        self.select_file_btn.setIcon(QIcon(r'D:/Nic/Safe Lookup/파일선택아이콘.png')) # 파일선택 아이콘
        self.select_file_btn.setIconSize(QSize(50, 50))  # 아이콘 크기 설정        
        self.select_file_btn.clicked.connect(self.select_file)
        hbox.addWidget(self.select_file_btn)
        
        
        # 파일 자동검사(마지막파일) 버튼 추가
        self.scan_file_btn = QPushButton(self)
        self.scan_file_btn.setIcon(QIcon(r'D:/Nic/Safe Lookup/파일검사아이콘.png')) # 파일 자동검사 아이콘
        self.scan_file_btn.setIconSize(QSize(50, 50))  # 아이콘 크기 설정
        self.scan_file_btn.clicked.connect(self.scan_last_file)
        hbox.addWidget(self.scan_file_btn)
        
        
        

        vbox.addLayout(hbox)
        vbox.addSpacing(90) # 파일 아이콘,버튼 여백 조절,이미지
        self.setLayout(vbox)

         # 버튼 크기를 픽셀로 직접 지정
        button_size = QSize(60, 60)  # 가로 60, 세로 60 픽셀 크기로 설정
        self.select_file_btn.setFixedSize(button_size)
        self.scan_file_btn.setFixedSize(button_size)

        

       
        
    # 파일 선택 함수
    def select_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "파일 선택", "", "All Files (*);;Python Files (*.py)", options=options)
        if file_name:
            self.scan_selected_file(file_name)

    # 선택한 파일을 스캔하는 함수
    def scan_selected_file(self, file_path):
        md5_hash = calculate_md5(file_path)
        result = scan_file(self.api_key, md5_hash)
        if result['response_code'] == 0:
            QMessageBox.information(self, "안내", "VirusTotal DB에 등록되지 않은 정보입니다.")
        elif result['response_code'] == 1:
            if result['positives'] > 0:
                QMessageBox.warning(self, "경고", "악성코드가 탐지되었습니다.")
                delete_file(file_path)
                QMessageBox.information(self, "알림", f"{file_path}가 정상적으로 삭제되었습니다.")
                self.display_report(result)
            else:
                QMessageBox.information(self, "안내", "파일이 안전합니다.")
        else:
            QMessageBox.information(self, "대기", "파일이 분석 대기중입니다. 나중에 다시 확인해주세요")

    # 파일 자동검사(마지막 파일을 스캔)하는 함수
    def scan_last_file(self):
        files = [os.path.join(self.directory_path, file) for file in os.listdir(self.directory_path) if os.path.isfile(os.path.join(self.directory_path, file))]
        if not files:
            QMessageBox.information(self, "정보", "파일이 존재하지 않습니다.")
            return

        download_times = {file: os.path.getctime(file) for file in files}
        files.sort(key=lambda x: download_times[x], reverse=False)

        last_file_path = files[-1]
        md5_hash = calculate_md5(last_file_path)
        result = scan_file(self.api_key, md5_hash)

        if result['response_code'] == 0:
            QMessageBox.information(self, "안내", "VirusTotal DB에 등록되지 않은 정보입니다.")
        elif result['response_code'] == 1:
            if result['positives'] > 0:
                QMessageBox.warning(self, "경고", "악성코드가 탐지되었습니다.")
                delete_file(last_file_path)
                QMessageBox.information(self, "알림", f"{last_file_path}가 정상적으로 삭제되었습니다.")
                self.display_report(result)
            else:
                QMessageBox.information(self, "안내", "파일이 안전합니다.")
        else:
            QMessageBox.information(self, "대기", "파일이 분석 대기중입니다. 나중에 다시 확인해주세요")

    
    def display_report(self, result): # 검사 보고서를 표시하는 함수
        report_window = QWidget()
        report_window.setWindowTitle("검사 보고서")
        report_window.setGeometry(100, 100, 800, 600)

        vbox = QVBoxLayout()

        table = QTableWidget()
        table.setRowCount(len(result['scans']))
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["엔진", "결과"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        row = 0
        for engine, details in result['scans'].items():
            if details['detected']:
                table.setItem(row, 0, QTableWidgetItem(engine))
                table.setItem(row, 1, QTableWidgetItem(details['result']))
                row += 1

        table.setRowCount(row)  
        vbox.addWidget(table)

        report_window.setLayout(vbox)
        report_window.show()

        self.report_window = report_window  
 

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = VirusTotalApp()
    ex.show()
    sys.exit(app.exec_())


