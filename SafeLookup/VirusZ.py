import tkinter as tk
from tkinter import messagebox
import requests
import os
import hashlib
from datetime import datetime, timezone

def calculate_md5(filename): # 파일 MD5 값을 계산하는 함수
    with open(filename, "rb") as f: 
        md5_hash = hashlib.md5()
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def delete_file(file_path): # 파일 삭제 함수
    try:
        os.remove(file_path) # 파일 삭제
        print(f"File {file_path} deleted successfully.")
    except FileNotFoundError: # 파일 찾을수 없음
        print(f"File {file_path} not found.") 
    except PermissionError:# 파일 삭제 권한 X
        print(f"No permission to delete file {file_path}.") 
    except Exception as e: # 다른 모든 예외 처리 블록
        print(f"An error occurred while deleting file {file_path}: {e}") 

def generate_scan_report(file_path, md5_hash, result):
    scan_date_utc = datetime.strptime(result['scan_date'], "%Y-%m-%d %H:%M:%S")
    scan_date_local = scan_date_utc.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    report = f"File: {file_path}\nMD5 Hash: {md5_hash}\nDetection Ratio: {result['positives']}/{result['total']}\nScan Date (Local Time): {scan_date_local}\n\n" # 파일 경로, md5값, 바이러스 검출한 엔진 수 / 총 엔진 수 , 스캔 시간
    report += "Detected Engines:\n"
    for engine, result_str in result['scans'].items(): # 스캔 결과에서 엔진 이름과 엔진이 검출한 결과를 반복해서 return
        report += f"{engine}: {result_str['result']}\n"
    return report

# 디렉토리 경로 설정
directory_path = 'C:/Users/Nicboy/Downloads' # 보안폴더 경로
# 디렉토리 내의 파일을 리스트업
files = [os.path.join(directory_path, file) for file in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, file))]
download_times = {file: os.path.getctime(file) for file in files} # 파일 다운로드 시간 기록
files.sort(key=lambda x: download_times[x], reverse=False) # 다운로드 시간 기준으로 파일 정렬
print(files)

# 마지막 파일에 대해서만 MD5 해시값 계산
last_file_path = files[-1] # 마지막 다운받은 파일 경로
md5_hash = calculate_md5(last_file_path) # MD5값 계산
print(f"File: {last_file_path}, MD5 Hash: {md5_hash}")

def scan_file(api_key, md5_hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report' # 스캔 결과를 요청하기 위한 경로
    params = {'apikey': api_key, 'resource': md5_hash} # 매개변수 api key와 md5 값 전달
    response = requests.get(url, params=params) # 지정된 url로 get 요청
    return response.json() # 응답 json 형식으로 반환

def button_click():
    api_key = 'fc4409575b69a4466c292c6a6b93a69bc8bb0cd421390b3ea10150938b8ff3cb'
    result = scan_file(api_key, md5_hash)
    
    if result['response_code'] == 0: # response_code 필드 0 : Virustotal DB에 등록 X [DB에 없거나 요청오류] , 1 : Virustotal DB에 등록 [악성코드] , -2 : 파일분석 대기 
        messagebox.showinfo("안내","VirusTotal DB에 등록되지 않은 정보입니다.")
    elif result['response_code'] == 1:
        if result['positives'] > 0: # positives 필드 : 파일이 악성코드로 감지된 백신 엔진 수 positives : 0 어떤 백신엔진도 악성코드로 감지 x , positive >= 1 백신 엔진 감지 수
            messagebox.showinfo("경고","악성코드가 탐지되었습니다.")
            delete_file(last_file_path)
            messagebox.showinfo("알림", f"{files[-1]}가 정상적으로 삭제되었습니다.")
            # 검사 결과 출력
            report = generate_scan_report(last_file_path, md5_hash, result)
            messagebox.showinfo("검사 보고서", report)
        else:   
            messagebox.showinfo("안내","파일이 안전합니다.")
    else:
        messagebox.showinfo("대기","파일이 분석 대기중입니다. 나중에 다시 확인해주세요") # positive 필드 음수인 경우 분석 대기

# Tkinter 윈도우 생성
root = tk.Tk()
root.title("바이러스 검사")

# 윈도우 크기 설정
window_width = 300
window_height = 200

# 화면 가운데로 윈도우 배치
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x = (screen_width / 2) - (window_width / 2)
y = (screen_height / 2) - (window_height / 2)

root.geometry(f"{window_width}x{window_height}+{int(x)}+{int(y)}")

# 버튼 생성
button = tk.Button(root, text="검사", command=button_click)
button.pack(pady=50)

# 윈도우 실행
root.mainloop()






