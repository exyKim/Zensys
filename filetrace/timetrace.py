import os
import time
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 감시할 경로를 사용자로부터 입력받습니다.
user_input_path = input("감시할 폴더 또는 파일 경로를 입력하세요: ")

# 입력된 경로가 파일인지 폴더인지 확인하고 WATCH_DIR 변수를 설정합니다.
if os.path.isfile(user_input_path):
    # 만약 파일 경로라면, 파일이 속한 폴더를 감시 대상으로 설정합니다.
    WATCH_DIR = os.path.dirname(user_input_path)
    print(f"파일 경로를 입력하셨습니다. 해당 파일이 있는 폴더 '{WATCH_DIR}'를 감시합니다.")
elif os.path.isdir(user_input_path):
    # 만약 폴더 경로라면, 그대로 감시 대상으로 설정합니다.
    WATCH_DIR = user_input_path
else:
    # 존재하지 않는 경로라면, 폴더를 새로 생성하기 위해 그대로 설정합니다.
    WATCH_DIR = user_input_path
    print(f"'{WATCH_DIR}' 폴더가 존재하지 않아 새로 생성합니다.")
    
# ------------------------------
# 실행 시 사용자 입력 받기 (근무시간)
# ------------------------------
try:
    # 문자열로 '시:분'을 입력받습니다 (예: 9:30, 18:00)
    WORK_START_STR = input("근무 시작 시간 (HH:MM): ")
    WORK_END_STR = input("근무 종료 시간 (HH:MM): ")

    # 문자열을 파싱하여 시간과 분을 분리합니다.
    start_hour, start_minute = map(int, WORK_START_STR.split(':'))
    end_hour, end_minute = map(int, WORK_END_STR.split(':'))

    # 시작 시간과 종료 시간을 모두 '분' 단위로 변환합니다.
    WORK_START_MIN = start_hour * 60 + start_minute
    WORK_END_MIN = end_hour * 60 + end_minute

    # 범위 및 논리 검증
    if not (0 <= start_hour <= 23 and 0 <= start_minute <= 59 and \
            0 <= end_hour <= 23 and 0 <= end_minute <= 59):
        print("[ERROR] 근무 시간은 'HH:MM' 형식으로 입력해야 하며, 유효한 시간 범위(00:00~23:59)여야 합니다. 프로그램을 종료합니다.")
        exit(1)

    if WORK_START_MIN >= WORK_END_MIN:
        print("[ERROR] 근무 시작 시간은 종료 시간보다 빨라야 합니다. 프로그램을 종료합니다.")
        exit(1)

except ValueError:
    print("[ERROR] 'HH:MM' 형식에 맞게 숫자로 입력해야 합니다. 프로그램을 종료합니다.")
    exit(1)

# ------------------------------
# 파일 해시 계산 함수
# ------------------------------
def calculate_file_hash(file_path):
    """SHA-256 Hash"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "N/A"

# ------------------------------
# 근무 시간 외인지 확인하는 함수 (수정)
# ------------------------------
def is_outside_working_hours():
    """현재 시간이 근무시간 외인지 확인"""
    # 현재 시간을 '분' 단위로 변환합니다.
    current_time_in_minutes = datetime.now().hour * 60 + datetime.now().minute
    
    # 변환된 값으로 근무 시간 외인지 확인합니다.
    return not (WORK_START_MIN <= current_time_in_minutes < WORK_END_MIN)

# ------------------------------
# 이벤트 핸들러
# ------------------------------
class SensitiveAccessHandler(FileSystemEventHandler):
    def log_event(self, signature, event_desc, action, file_path):
        try:
            user_name = os.getlogin()
        except OSError:
            user_name = "Unknown"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_name = os.path.basename(file_path) if os.path.exists(file_path) else os.path.basename(file_path)
        file_hash = calculate_file_hash(file_path) if os.path.exists(file_path) else "N/A"

        # 로그 포맷
        log_message = (
            f"[{signature}] \"{event_desc}\" {timestamp} DK='ALL' "
            f"/ User={user_name}, File={file_name}, Hash={file_hash}, Action={action}"
        )
        print(log_message)

    def on_modified(self, event):
        if is_outside_working_hours() and not event.is_directory:
            self.log_event("T", "문서 수정 탐지", "MODIFIED", event.src_path)

    def on_deleted(self, event):
        if is_outside_working_hours() and not event.is_directory:
            self.log_event("T", "문서 삭제 탐지", "DELETED", event.src_path)


# ------------------------------
# 메인 실행
# ------------------------------
if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = SensitiveAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)

    print(f"[*] Monitoring folder: {WATCH_DIR}")
    print(f"[*] Working hours: {WORK_START_STR} ~ {WORK_END_STR}")
    print("[*] Detect Target: ALL FILES")
    print("[*] Waiting for suspicious activity outside working hours...\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()