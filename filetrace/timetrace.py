import os
import time
import hashlib
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ----------------------------- 유틸 -----------------------------
def iso_now() -> str:
    """타임존 포함 ISO 포맷(초 단위)."""
    return datetime.now().astimezone().isoformat(timespec="seconds")

### 수정: 사람이 읽기 좋은 시간 포맷 추가
def pretty_now() -> str:
    """YYYY-MM-DD HH:MM:SS (TZ) 형식 로컬 시간."""
    now = datetime.now().astimezone()
    tz = now.tzname() or ""
    return f"{now.strftime('%Y-%m-%d %H:%M:%S')} ({tz})"

def current_identity() -> Dict[str, str]:
    """사용자/도메인/호스트/PID 최소 식별 정보."""
    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    domain = os.environ.get("USERDOMAIN") or os.environ.get("DOMAIN") or ""
    host = platform.node() or os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown-host"
    pid = str(os.getpid())
    return {"user": user, "domain": domain, "host": host, "pid": pid}

def calculate_file_hash(p: Path) -> str:
    """SHA-256 해시 계산(실패 시 'N/A')."""
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"

def normalize_dir_input(raw: str) -> Path:
    """입력 경로 정규화(따옴표/공백 제거, ~, %VAR% 확장, 절대경로화)."""
    s = raw.strip().strip('"').strip("'")
    s = os.path.expandvars(os.path.expanduser(s))
    return Path(s).resolve()

# ----------------------------- 근무시간 -----------------------------
def parse_work_time(hhmm: str) -> Optional[int]:
    """'HH:MM' → 분(min) 단위. 형식/범위 오류 시 None."""
    try:
        hh, mm = map(int, hhmm.split(":"))
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh * 60 + mm
    except Exception:
        pass
    return None

### 수정: wrap-around(자정 넘김) 지원
def is_outside_working_hours(start_min: int, end_min: int) -> bool:
    """
    현재 시간이 근무시간 외인지 (wrap-around 지원).
    - 일반: start < end (예: 09:00~18:00)
    - 자정 넘김: start > end (예: 22:00~06:00)
    - start == end: 24시간 근무로 간주
    """
    cur = datetime.now().hour * 60 + datetime.now().minute
    if start_min == end_min:
        return False  # 24시간 근무
    if start_min < end_min:
        return not (start_min <= cur < end_min)
    else:
        in_work = (cur >= start_min) or (cur < end_min)
        return not in_work

# ----------------------------- 로그 포맷터 -----------------------------
def print_event_block(signature: str, event_desc: str, action: str, file_path: Path, work_range: str):
    ident = current_identity()
    ts = iso_now()
    ts_pretty = pretty_now()   ### 수정: 사람이 읽기 쉬운 시간 추가
    name = file_path.name
    fhash = calculate_file_hash(file_path) if file_path.exists() else "N/A"

    # 요약 + 사람이 읽기 쉬운 로그
    print("\n" + "=" * 60)
    print(f"{signature}/ {action} {ts} DK='ALL' / user '{ident['user']}' / host '{ident['host']}'")
    print(f"LocalTime : {ts_pretty}")   ### 수정: 로그에 현지 시각 출력
    dom_user = (ident['domain'] + '\\\\') if ident['domain'] else ''
    dom_user += ident['user']
    print(f"[{signature}] {event_desc}")
    print(f"    Action    : {action}")
    print(f"    File      : {name}")
    print(f"    Path      : {str(file_path)}")
    print(f"    Hash      : {fhash}")
    print(f"    User      : {dom_user}")
    print(f"    Host      : {ident['host']}")
    print(f"    PID       : {ident['pid']}")
    print(f"    WorkTime  : {work_range}")

    # JSON 구조 로그
    print("\n[JSON]")
    j = {
        "ts": ts,
        "ts_local": ts_pretty,   
        "action": action,
        "file": str(file_path),
        "file_name": name,
        "hash": fhash,
        "dk": "ALL",
        "user": ident["user"],
        "domain": ident["domain"],
        "host": ident["host"],
        "pid": ident["pid"],
        "work_time": work_range,
        "reason": "outside_working_hours"
    }
    import json
    print(json.dumps(j, ensure_ascii=False, indent=2))
    print("=" * 60 + "\n")


class SensitiveAccessHandler(FileSystemEventHandler):
    """
    근무시간 외에 발생한 파일 '수정/삭제' 이벤트만 기록.
    """
    def __init__(self, work_start_min: int, work_end_min: int, work_range_label: str):
        super().__init__()
        self.work_start_min = work_start_min
        self.work_end_min = work_end_min
        self.work_range_label = work_range_label

    def _should_log(self) -> bool:
        return is_outside_working_hours(self.work_start_min, self.work_end_min)

    def on_modified(self, event):
        if not event.is_directory and self._should_log():
            print_event_block("T", "문서 수정 탐지", "MODIFIED", Path(event.src_path), self.work_range_label)

    def on_deleted(self, event):
        if not event.is_directory and self._should_log():
            print_event_block("T", "문서 삭제 탐지", "DELETED", Path(event.src_path), self.work_range_label)

# ----------------------------- 메인 -----------------------------
if __name__ == "__main__":
    # 1) 경로 입력 & 정규화
    raw_path = input("감시할 폴더 또는 파일 경로를 입력하세요: ").strip()
    if not raw_path:
        raw_path = r"C:\sensitiveFile"
    p = normalize_dir_input(raw_path)

    # 파일을 주면 폴더로 전환
    if p.is_file():
        watch_dir = p.parent
        print(f"파일 경로를 입력하셨습니다. 해당 파일이 있는 폴더 '{watch_dir}'를 감시합니다.")
    else:
        watch_dir = p
        if not watch_dir.exists():
            print(f"'{watch_dir}' 폴더가 존재하지 않아 새로 생성합니다.")
            watch_dir.mkdir(parents=True, exist_ok=True)

    # 2) 근무시간 입력 & 검증 (wrap-around 허용)
    work_start_str = input("근무 시작 시간 (HH:MM): ").strip()
    work_end_str   = input("근무 종료 시간 (HH:MM): ").strip()
    ws = parse_work_time(work_start_str)
    we = parse_work_time(work_end_str)
    if ws is None or we is None:
        print("[ERROR] 근무 시간은 'HH:MM' 형식으로 00:00~23:59 범위여야 합니다.")
        raise SystemExit(1)
    if ws == we:
        print("[WARN] 시작/종료가 동일합니다 (24시간 근무). 근무시간 외 트리거는 발생하지 않습니다.")
    work_range_label = f"{work_start_str}~{work_end_str}"

    # 3) 감시 시작
    handler = SensitiveAccessHandler(ws, we, work_range_label)
    observer = Observer()
    observer.schedule(handler, path=str(watch_dir), recursive=False)

    print(f"\n[*] Monitoring folder: {watch_dir}")
    print(f"[*] Working hours   : {work_range_label} (wrap-around 지원)")
    print("[*] Detect Target   : ALL FILES")
    print("[*] Trigger         : Outside working hours (MODIFIED / DELETED)\n")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
