import os
import time
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = r"C:\sensitiveFile"
SENSITIVE_KEYWORD = "ask2025"

total_sensitive_accesses = 0
successful_detections = 0

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

class SensitiveAccessHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global total_sensitive_accesses, successful_detections

        if not event.is_directory and SENSITIVE_KEYWORD in os.path.basename(event.src_path):
            total_sensitive_accesses += 1
            start_time = time.time()

            try:
                user_name = os.getlogin()
            except OSError:
                user_name = "Unknown"

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_name = os.path.basename(event.src_path)
            file_hash = calculate_file_hash(event.src_path)
            detection_time = round(time.time() - start_time, 2)

            successful_detections += 1
            detection_rate = round((successful_detections / total_sensitive_accesses) * 100, 2)

            print("\n[ALERT] Sensitive Document Access Detected")
            print(f"- User Name: {user_name}")
            print(f"- File Name: {file_name}")
            print(f"- Timestamp: {timestamp}")
            print(f"- File Hash (SHA-256): {file_hash}")
            print(f"- Detection Time: {detection_time} seconds")
            print(f"- Current Detection Rate: {detection_rate}%")

    def on_deleted(self, event):
        global total_sensitive_accesses, successful_detections

        if not event.is_directory and SENSITIVE_KEYWORD in os.path.basename(event.src_path):
            total_sensitive_accesses += 1
            start_time = time.time()

            try:
                user_name = os.getlogin()
            except OSError:
                user_name = "Unknown"

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_name = os.path.basename(event.src_path)
            detection_time = round(time.time() - start_time, 2)

            successful_detections += 1
            detection_rate = round((successful_detections / total_sensitive_accesses) * 100, 2)

            print("\n[ALERT] Sensitive Document Deletion Detected")
            print(f"- User Name: {user_name}")
            print(f"- File Name: {file_name}")
            print(f"- Timestamp: {timestamp}")
            print(f"- Detection Time: {detection_time} seconds")
            print(f"- Current Detection Rate: {detection_rate}%")

if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)  # 폴더가 없으면 자동 생성
    event_handler = SensitiveAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)

    print(f"[*] Monitoring folder: {WATCH_DIR}")
    print("[*] Waiting for access to sensitive documents...\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
