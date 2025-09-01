import os 
import time
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_DIR = input("감시할 폴더 경로를 입력하세요 (예: C:\\sensitiveFile): ").strip()
if not WATCH_DIR:
    WATCH_DIR = r"C:\sensitiveFile"


ext_input = input("민감한 확장자들을 입력하세요 (예: .docx,.pdf,.hwp): ").strip()
SENSITIVE_EXTENSIONS = [e.strip().lower() for e in ext_input.split(",") if e.strip()]


keyword_input = input("민감한 파일 키워드를 입력하세요 (예: secret): ").strip()
SENSITIVE_KEYWORDS = [k.strip().lower() for k in keyword_input.split(",") if k.strip()]


def calculate_file_hash(file_path):  #파일을 4KB 단위로 읽어서 SHA-256 해시 계산
    """SHA-256 Hash"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "N/A"


def is_sensitive(file_path): # 이 함수가 "이 파일을 민감한 파일로 간주할지 최종 결정"
    filename = os.path.basename(file_path).lower()
    ext = os.path.splitext(file_path)[1].lower()

    if ext in SENSITIVE_EXTENSIONS:
        return True
    if any(keyword in filename for keyword in SENSITIVE_KEYWORDS):
        return True
    return False


class SensitiveAccessHandler(FileSystemEventHandler):
    def log_event(self, action, file_path):
        try:
            user_name = os.getlogin()
        except OSError:
            user_name = "Unknown"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ext = os.path.splitext(file_path)[1].lower() or "N/A"

        # 로그 출력 (시그니처 [D] 형식)
        print(f"[D] \"Document Detect Alert - {action}\" {timestamp} DK='{ext}' / user '{user_name}'")

    def on_modified(self, event):
        if not event.is_directory and is_sensitive(event.src_path):
            self.log_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and is_sensitive(event.src_path):
            self.log_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory and is_sensitive(event.dest_path):
            self.log_event("MOVED/RENAMED", event.dest_path)


if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = SensitiveAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)

    print(f"\n[*] Monitoring folder: {WATCH_DIR}")
    print(f"[*] Sensitive Extensions: {SENSITIVE_EXTENSIONS}")
    print(f"[*] Sensitive Keywords: {SENSITIVE_KEYWORDS}")
    print("[*] Waiting for file activity...\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
