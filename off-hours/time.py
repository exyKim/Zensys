import os
import time
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = r"C:\sensitiveFile"

# ------------------------------
# 실행 시 사용자 입력 받기 (근무시간)
# ------------------------------
try:
    WORK_START = int(input("근무 시작 시간 (0~23): "))
    WORK_END = int(input("근무 종료 시간 (0~23): "))

    # 범위 검증
    if not (0 <= WORK_START <= 23 and 0 <= WORK_END <= 23):
        print("[ERROR] 근무 시간은 0~23 사이 정수여야 합니다. 프로그램을 종료합니다.")
        exit(1)

    # 논리 검증 (시작 >= 종료 → 잘못된 입력)
    if WORK_START >= WORK_END:
        print("[ERROR] 근무 시작 시간은 종료 시간보다 작아야 합니다. 프로그램을 종료합니다.")
        exit(1)

except ValueError:
    print("[ERROR] 숫자로 입력해야 합니다. 프로그램을 종료합니다.")
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


def is_outside_working_hours():
    """현재 시간이 근무시간 외인지 확인"""
    current_hour = datetime.now().hour
    return not (WORK_START <= current_hour < WORK_END)


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
        file_name = os.path.basename(file_path)
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


# ------------------------------
# 메인 실행
# ------------------------------
if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = SensitiveAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)

    print(f"[*] Monitoring folder: {WATCH_DIR}")
    print(f"[*] Working hours: {WORK_START}:00 ~ {WORK_END}:00")
    print("[*] Detect Target: ALL FILES")
    print("[*] Waiting for suspicious activity outside working hours...\n")

    observer.start()
    try:
        while True:
            time.sleep(1)

            # 근무 종료 시간이 되면 자동 종료
            current_hour = datetime.now().hour
            if current_hour >= WORK_END:
                print(f"\n[*] 근무 종료 시간({WORK_END}:00) 지남 → 프로그램 자동 종료")
                observer.stop()
                break

    except KeyboardInterrupt:
        observer.stop()

    observer.join()
