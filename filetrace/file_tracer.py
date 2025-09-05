import os
import time
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


def calculateFileHash(filePath):
    """
    파일의 SHA-256 해시를 계산합니다.
    """
    sha256Hash = hashlib.sha256()
    try:
        with open(filePath, "rb") as file:
            for byteBlock in iter(lambda: file.read(4096), b""):
                sha256Hash.update(byteBlock)
        return sha256Hash.hexdigest()
    except Exception:
        return "N/A"


class SensitiveAccessHandler(FileSystemEventHandler):
    """
    민감한 파일에 대한 파일 시스템 이벤트를 처리하는 클래스
    """
    def __init__(self, mode, rules):
        super().__init__()
        self.detectionMode = mode
        self.detectionRules = rules

    def isSensitive(self, filePath):
        """
        파일이 설정된 규칙에 따라 민감한지 확인
        """
        fileName = os.path.basename(filePath).lower()
        fileExtension = os.path.splitext(filePath)[1].lower()

        if self.detectionMode == "ext":
            # 확장자 기반 검사
            return fileExtension in self.detectionRules
        elif self.detectionMode == "kw":
            # 키워드 기반 검사
            return any(keyword in fileName for keyword in self.detectionRules)
        return False

    def logEvent(self, action, filePath, detectedKeyword=""):
        """
        파일 접근 이벤트를 요청된 형식의 로그로 기록
        """
        try:
            userName = os.getlogin()
        except OSError:
            userName = "Unknown"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fileName = os.path.basename(filePath)
        fileHash = calculateFileHash(filePath) if os.path.exists(filePath) else "N/A"

        print(
            f"D/ {action} {timestamp} "
            f"DK='{detectedKeyword}' / user '{userName}'"
        )
        print(f"[D] Document Detect Alert - {action}")
        print(f"Timestamp: {timestamp}")
        print(f"File: {fileName}")
        print(f"Hash: {fileHash}")
        print(f"User: {userName}")
        print(f"DK: {detectedKeyword}")
        print("-" * 20)

    def on_created(self, event):
        if not event.is_directory and self.isSensitive(event.src_path):
            detectedItem = os.path.splitext(event.src_path)[1].lower() if self.detectionMode == "ext" else os.path.basename(event.src_path).lower()
            self.logEvent("CREATED", event.src_path, detectedItem)

    def on_modified(self, event):
        if not event.is_directory and self.isSensitive(event.src_path):
            detectedItem = os.path.splitext(event.src_path)[1].lower() if self.detectionMode == "ext" else os.path.basename(event.src_path).lower()
            self.logEvent("MODIFIED", event.src_path, detectedItem)

    def on_deleted(self, event):
        if not event.is_directory and self.isSensitive(event.src_path):
            detectedItem = os.path.splitext(event.src_path)[1].lower() if self.detectionMode == "ext" else os.path.basename(event.src_path).lower()
            self.logEvent("DELETED", event.src_path, detectedItem)

    def on_moved(self, event):
        if not event.is_directory and self.isSensitive(event.dest_path):
            detectedItem = os.path.splitext(event.dest_path)[1].lower() if self.detectionMode == "ext" else os.path.basename(event.dest_path).lower()
            self.logEvent("MOVED/RENAMED", event.dest_path, detectedItem)


if __name__ == "__main__":
    # 감시 폴더 설정
    watchDirectory = input("감시할 폴더 경로를 입력하세요 (예: C:\\sensitiveFile): ").strip()
    if not watchDirectory:
        watchDirectory = r"C:\sensitiveFile"
    
    # 사용자가 입력한 경로가 존재하지 않으면 프로그램 종료
    if not os.path.isdir(watchDirectory):
        print(f"[ERROR] '{watchDirectory}' 폴더가 존재하지 않습니다. 프로그램을 종료합니다.")
        exit(1)
        
    modeInput = input("기밀문서 설정 방식을 선택하세요 (확장자 / 파일이름): ").strip()
    if modeInput == "확장자":
        rulesInput = input("민감한 확장자들을 입력하세요 (예: .docx,.pdf,.hwp): ").strip()
        detectionRules = [e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
                          for e in rulesInput.split(",") if e.strip()]
        detectionMode = "ext"
    elif modeInput == "파일이름":
        rulesInput = input("민감한 파일 키워드를 입력하세요 (예: secret,plan,기밀): ").strip()
        detectionRules = [k.strip().lower() for k in rulesInput.split(",") if k.strip()]
        detectionMode = "kw"
    else:
        print("[ERROR] 잘못된 입력입니다. '확장자' 또는 '파일이름' 중 하나를 입력하세요.")
        exit(1)

    eventHandler = SensitiveAccessHandler(detectionMode, detectionRules)
    observer = Observer()
    observer.schedule(eventHandler, path=watchDirectory, recursive=False)

    print("\n[*] Monitoring folder:", watchDirectory)
    print("[*] Mode:", "확장자 기반" if detectionMode == "ext" else "파일이름 기반")
    print("[*] Rules:", detectionRules)
    print("[*] Waiting for file activity...\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()