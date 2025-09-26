import os
import time
import hashlib
import getpass
import json
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ----------------------------- 유틸 -----------------------------
def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

def current_identity() -> Dict[str, str]:
    """
    사용자/도메인/호스트/PID 최소 식별정보.
    외부 라이브러리 없이 동작, 실패 시 'unknown' 처리.
    """
    # user
    try:
        user = getpass.getuser() or os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    # domain (Windows 위주, mac/linux는 보통 비어있음)
    domain = os.environ.get("USERDOMAIN") or os.environ.get("DOMAIN") or ""
    # host
    host = platform.node() or os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown-host"
    # pid
    pid = str(os.getpid())
    return {"user": user, "domain": domain, "host": host, "pid": pid}

def calculate_file_hash(file_path: Path) -> str:
    try:
        sha256_hash = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception:
        return "N/A"

# ----------------------------- 리포지토리 (DB 자리) -----------------------------
class EventRepository:
    """
    실제 DB로 교체할 인터페이스.
    - insert_event: 이벤트 저장 → {"event_id": int, "stored_at": iso8601}
    - load_rules: (선택) 규칙을 DB에서 읽어올 때 사용
    """
    def insert_event(self, event_data: Dict) -> Dict:
        raise NotImplementedError

    def load_rules(self, mode: str) -> Optional[Set[str]]:
        return None

class InMemoryEventRepository(EventRepository):
    """
    DB가 없으므로 임시 메모리 저장. 자동 증가 ID로 DB 흉내.
    """
    def __init__(self):
        self._auto_id = 0
        self._rows = []

    def insert_event(self, event_data: Dict) -> Dict:
        self._auto_id += 1
        stored = {"event_id": self._auto_id, "stored_at": iso_now()}
        row = {**event_data, **stored}
        self._rows.append(row)
        return stored

    def load_rules(self, mode: str) -> Optional[Set[str]]:
        return None

# ----------------------------- 파이프라인 -----------------------------
class SecurityPipeline:
    """
    감지 이벤트 처리:
    1) DB 저장 (event_id/시간 확보)
    2) 로그 출력(요약/사람용/JSON) — DB 반환값/사용자 메타 포함
    """
    def __init__(self, detection_mode: str, detection_rules: Set[str], repo: EventRepository):
        self.detection_mode = detection_mode  # "ext" | "kw"
        self.detection_rules = detection_rules
        self.repo = repo
        # DB에서 규칙을 읽고 싶다면 주석 해제
        # db_rules = self.repo.load_rules(self.detection_mode)
        # if db_rules:
        #     self.detection_rules = db_rules

    def handle_event(self, event_data: Dict):
        # 1) DB 저장
        db_result = self.repo.insert_event(event_data)
        event_id = db_result.get("event_id")
        stored_at = db_result.get("stored_at")

        # 2) 로그 출력 (가독성 개선)
        print("\n" + "=" * 60)   # 구분선 + 한 줄 띄우기

        # 요약 로그
        print(
            f"D/ {event_data['action']} {event_data['timestamp']} "
            f"DK='{event_data['detected_item']}' / user '{event_data.get('user','unknown')}' "
            f"/ host '{event_data.get('host','unknown-host')}' / id {event_id}"
        )

        # 사람이 읽기 쉬운 로그
        dom = event_data.get('domain') or ''
        dom_user = (dom + '\\\\') if dom else ''
        dom_user += event_data.get('user', 'unknown')

        print(f"[D] Action    : {event_data['action']}")
        print(f"    File      : {event_data['file_name']}")
        print(f"    Path      : {event_data['file_path']}")
        print(f"    Hash      : {event_data['file_hash']}")
        print(f"    User      : {dom_user}")
        print(f"    Host      : {event_data.get('host','unknown-host')}")
        print(f"    PID       : {event_data.get('pid','-')}")
        print(f"    StoredAt  : {stored_at}")
        print(f"    EventID   : {event_id}")

        # 구조화(JSON) 로그 (들여쓰기)
        print("\n[JSON]")
        j = {
            "ts": event_data["timestamp"],
            "action": event_data["action"],
            "file": event_data["file_path"],
            "file_name": event_data["file_name"],
            "hash": event_data["file_hash"],
            "detected_item": event_data["detected_item"],
            "user": event_data.get("user"),
            "domain": event_data.get("domain"),
            "host": event_data.get("host"),
            "pid": event_data.get("pid"),
            "db_event_id": event_id,
            "db_stored_at": stored_at,
        }
        print(json.dumps(j, ensure_ascii=False, indent=2))

        print("=" * 60 + "\n")   # 끝 구분선 + 줄 띄우기

# ----------------------------- 핸들러 -----------------------------
class SensitiveAccessHandler(FileSystemEventHandler):
    def __init__(self, pipeline: SecurityPipeline):
        super().__init__()
        self.pipeline = pipeline

    def is_sensitive(self, file_path: Path) -> bool:
        file_name = file_path.name.lower()
        ext = file_path.suffix.lower()
        if self.pipeline.detection_mode == "ext":
            return ext in self.pipeline.detection_rules
        elif self.pipeline.detection_mode == "kw":
            return any(kw in file_name for kw in self.pipeline.detection_rules)
        return False

    def generate_event_data(self, action: str, file_path: Path) -> Dict:
        file_hash = calculate_file_hash(file_path) if file_path.exists() else "N/A"
        detected_item = file_path.suffix.lower() if self.pipeline.detection_mode == "ext" else file_path.name.lower()
        ident = current_identity()
        return {
            "timestamp": iso_now(),
            "action": action,
            "file_name": file_path.name,
            "file_path": str(file_path),
            "file_hash": file_hash,
            "detected_item": detected_item,
            "user": ident["user"],
            "domain": ident["domain"],
            "host": ident["host"],
            "pid": ident["pid"],
        }

    # 이벤트 훅들 (생성/수정/삭제/이동) — 수정 포함
    def on_created(self, event):
        if not event.is_directory and self.is_sensitive(Path(event.src_path)):
            self.pipeline.handle_event(self.generate_event_data("CREATED", Path(event.src_path)))

    def on_modified(self, event):
        if not event.is_directory and self.is_sensitive(Path(event.src_path)):
            self.pipeline.handle_event(self.generate_event_data("MODIFIED", Path(event.src_path)))

    def on_deleted(self, event):
        if not event.is_directory and self.is_sensitive(Path(event.src_path)):
            self.pipeline.handle_event(self.generate_event_data("DELETED", Path(event.src_path)))

    def on_moved(self, event):
        if not event.is_directory and self.is_sensitive(Path(event.dest_path)):
            self.pipeline.handle_event(self.generate_event_data("MOVED", Path(event.dest_path)))

# ----------------------------- 엔트리포인트 -----------------------------
if __name__ == "__main__":
    watch_directory = input("감시할 폴더 경로를 입력하세요 (예: C:\\sensitiveFile): ").strip() or r"C:\sensitiveFile"
    if not os.path.isdir(watch_directory):
        print(f"[ERROR] '{watch_directory}' 폴더가 존재하지 않습니다.")
        raise SystemExit(1)

    mode_input = input("기밀문서 설정 방식을 선택하세요 (확장자 / 파일이름): ").strip()
    if mode_input == "확장자":
        rules_input = input("민감한 확장자들을 입력하세요 (예: .docx,.pdf,.hwp): ").strip()
        detection_rules = {
            e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
            for e in rules_input.split(",") if e.strip()
        }
        detection_mode = "ext"
    elif mode_input == "파일이름":
        rules_input = input("민감한 파일 키워드를 입력하세요 (예: secret,plan,기밀): ").strip()
        detection_rules = {k.strip().lower() for k in rules_input.split(",") if k.strip()}
        detection_mode = "kw"
    else:
        print("[ERROR] 잘못된 입력입니다. '확장자' 또는 '파일이름' 중 하나를 입력하세요.")
        raise SystemExit(1)

    # 지금은 인메모리 DB. 실제 DB 붙일 때만 아래 한 줄 교체.
    # repo = RealSQLEventRepository(sessionmaker(...))
    repo = InMemoryEventRepository()

    pipeline = SecurityPipeline(detection_mode, detection_rules, repo)
    event_handler = SensitiveAccessHandler(pipeline)

    observer = Observer()
    observer.schedule(event_handler, path=watch_directory, recursive=False)

    print("\n[*] Monitoring:", watch_directory)
    print("[*] Mode:", detection_mode)
    print("[*] Rules:", detection_rules)
    print("[*] Waiting for file activity... (Ctrl+C to exit)\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join() 