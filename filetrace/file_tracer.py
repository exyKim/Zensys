import os
import time
import hashlib
import getpass
import json
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, Optional  # Optional은 남겨둬도 무방

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
    try:
        user = getpass.getuser() or os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    domain = os.environ.get("USERDOMAIN") or os.environ.get("DOMAIN") or ""
    host = platform.node() or os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown-host"
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

# ----------------------------- 노이즈 필터 -----------------------------
NOISY_SUFFIX = ('.tmp', '.crdownload')
def is_noisy(p: Path) -> bool:
    n = p.name.lower()
    return n.startswith('~$') or n.endswith(NOISY_SUFFIX)

# ----------------------------- 리포지토리 (DB 자리) -----------------------------
class EventRepository:
    def insert_event(self, event_data: Dict) -> Dict:
        raise NotImplementedError
    def load_rules(self, mode: str) -> Optional[Set[str]]:
        return None

class InMemoryEventRepository(EventRepository):
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
    1) 저장 리포지토리 호출(현재는 메모리) → event_id/시간 확보
    2) 로그 출력(요약/사람용/JSON)
    """
    def __init__(self, detection_mode: str, detection_rules: Set[str], repo: EventRepository):
        self.detection_mode = detection_mode  # "ext" | "kw"
        self.detection_rules = detection_rules
        self.repo = repo

    def handle_event(self, event_data: Dict):
        db_result = self.repo.insert_event(event_data)
        event_id = db_result.get("event_id")
        stored_at = db_result.get("stored_at")

        print("\n" + "=" * 60)
        print(
            f"D/ {event_data['action']} {event_data['timestamp']} "
            f"DK='{event_data['detected_item']}' / user '{event_data.get('user','unknown')}' "
            f"/ host '{event_data.get('host','unknown-host')}' / id {event_id}"
        )

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
        print("=" * 60 + "\n")

# ----------------------------- 핸들러 -----------------------------
class SensitiveAccessHandler(FileSystemEventHandler):
    def __init__(self, pipeline: SecurityPipeline, debounce_sec: float = 1.5):
        super().__init__()
        self.pipeline = pipeline
        self._gap = debounce_sec
        self._last_emit: Dict[str, float] = {}   # 파일별 최근 이벤트 시각

    # 디바운스
    def _debounced(self, p: Path, action: str) -> bool:
        now = time.time()
        k = f"{str(p)}|{action}"
        last = self._last_emit.get(k, 0.0)
        if now - last < self._gap:
            return True
        self._last_emit[k] = now
        return False

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
        detected_item = (
            file_path.suffix.lower()
            if self.pipeline.detection_mode == "ext"
            else file_path.name.lower()
        )
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

    
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if is_noisy(path) or self._debounced(path, "CREATED"):
            return
        if self.is_sensitive(path):
            self.pipeline.handle_event(self.generate_event_data("CREATED", path))

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if is_noisy(path) or self._debounced(path, "MODIFIED"):
            return
        if self.is_sensitive(path):
            self.pipeline.handle_event(self.generate_event_data("MODIFIED", path))

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if is_noisy(path) or self._debounced(path, "DELETED"):
            return
        if self.is_sensitive(path):
            self.pipeline.handle_event(self.generate_event_data("DELETED", path))

    def on_moved(self, event):
        if event.is_directory:
            return
        src, dst = Path(event.src_path), Path(event.dest_path)
        if (is_noisy(src) and is_noisy(dst)) or self._debounced(dst, "MOVED"):
            return
        if self.is_sensitive(src) or self.is_sensitive(dst):
            self.pipeline.handle_event(self.generate_event_data("MOVED", dst))

# ----------------------------- 엔트리포인트 -----------------------------
if __name__ == "__main__":
    # 감시 경로 입력
    watch_directory = input("감시할 폴더 경로를 입력하세요 (예: C:\\sensitiveFile): ").strip() or r"C:\sensitiveFile"
    if not os.path.isdir(watch_directory):
        print(f"[ERROR] '{watch_directory}' 폴더가 존재하지 않습니다.")
        raise SystemExit(1)

    # 기밀문서 탐지 방식
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

    # 저장소: 지금은 인메모리. 나중에 실제 DB 리포지토리로 교체.
    repo = InMemoryEventRepository()

    pipeline = SecurityPipeline(detection_mode, detection_rules, repo)
    event_handler = SensitiveAccessHandler(
        pipeline,
        debounce_sec=1.5,   # 필요시 2~3초로 늘리면 중복 더 줄어듦
    )

    observer = Observer()
    observer.schedule(event_handler, path=watch_directory, recursive=False)

    print("\n[*] Monitoring:", watch_directory)
    print("[*] Mode:", detection_mode)
    print("[*] Rules:", detection_rules)
    print("[*] Filters: noisy(~$, *.tmp, *.crdownload), debounce=1.5s")
    print("[*] Waiting for file activity... (Ctrl+C to exit)\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
