import sys
import requests
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import Qt


class URLScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle('URL Scanner')
        self.setGeometry(100, 100, 800, 600)

        # Set dark theme
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(45, 45, 45))
        palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(45, 45, 45))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

        # Layout setup
        layout = QVBoxLayout()

        font = QFont()
        font.setPointSize(16)

        self.url_label = QLabel('URL 검색')
        self.url_label.setFont(font)
        self.url_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.url_label)

        self.url_entry = QLineEdit(self)
        self.url_entry.setFont(font)
        self.url_entry.setPlaceholderText('URL 입력')
        self.url_entry.setStyleSheet("background-color: white; color: black;")
        layout.addWidget(self.url_entry)

        self.scan_button = QPushButton('주소 스캔', self)
        self.scan_button.setStyleSheet("color: black;")
        self.scan_button.setFont(font)
        self.scan_button.clicked.connect(self.scan_url)
        layout.addWidget(self.scan_button)

        self.result_label = QLabel('')
        self.result_label.setFont(font)
        self.result_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.result_label)

        self.analysis_text = QTextEdit()
        self.analysis_text.setFont(font)
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setStyleSheet("background-color: white; color: black;")
        layout.addWidget(self.analysis_text)

        self.setLayout(layout)

    def scan_url(self):
        url = self.url_entry.text()
        api_key = 'bebe13ab8877e329157be5a8de98b4ed44302db9cdb5263a4ec61a2d26d943c6'  # Replace with your own API key

        headers = {
            'x-apikey': api_key
        }

        # Step 1: Submit the URL for analysis
        submit_url = 'https://www.virustotal.com/api/v3/urls'
        response = requests.post(submit_url, headers=headers, data={'url': url})
        if response.status_code == 200:
            result = response.json()
            url_id = result['data']['id']
        else:
            self.result_label.setText(f"URL 제출 오류: {response.status_code}")
            return

        # Step 2: Retrieve the analysis results
        # URL을 base64로 인코딩하고 마지막 '='를 제거
        url_id_base64 = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        analysis_url = f'https://www.virustotal.com/api/v3/urls/{url_id_base64}'
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            positives = result['data']['attributes']['last_analysis_stats']['malicious']
            total = sum(result['data']['attributes']['last_analysis_stats'].values())

            # 거짓 양성 무효화
            if positives <= 1:
                self.result_label.setText("이 URL은 안전한 것으로 판단됩니다.")
            else:
                self.result_label.setText(f"스캔 결과: {positives}개의 스캐너가 해당 URL을 악성으로 감지했습니다. (총 {total}개의 스캐너 중)")

                # 상세 분석 결과 출력 (clean이 아닌 것만)
                self.analysis_text.clear()
                for scanner, result in result['data']['attributes']['last_analysis_results'].items():
                    if result['result'] != 'clean':
                        self.analysis_text.append(f"- {scanner}: {result['result']}")
        else:
            self.result_label.setText(f"분석 결과 가져오기 오류: {response.status_code}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = URLScanner()
    ex.show()
    sys.exit(app.exec_())
