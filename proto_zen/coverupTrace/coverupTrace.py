import os
import glob
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Set, List

# -------------------------------
# Config 로더 (json5 지원 + // 주석 허용)
# -------------------------------
def _strip_line_comments(text: str) -> str:
    import re
    return re.sub(r"//.*", "", text)

def load_config(path="coverup_so.json") -> dict:
    try:
        import json5
        with open(path, "r", encoding="utf-8") as f:
            return json5.load(f)
    except Exception:
        import json
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        return json.loads(_strip_line_comments(raw))

# -------------------------------
# 유틸
# -------------------------------
def now_local() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256_of(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def convention_line(text: str, dk: str, extra: str = "") -> str:
    tail = f" / {extra}" if extra else ""
    return f"[C] \"{text}\" {now_local()} DK='{dk}'{tail}"

def _norm_ext(e: str) -> str:
    e = e.lower().strip()
    return e[1:] if e.startswith(".") else e

def _expand_watch_dirs(patterns: List[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        exp = os.path.expandvars(os.path.expanduser(pat))
        matches = glob.glob(exp, recursive=True)
        if not matches:
            if os.path.isdir(exp):
                out.append(Path(exp))
        else:
            for m in matches:
                if os.path.isdir(m):
                    out.append(Path(m))
    # dedupe (realpath)
    seen = set()
    uniq: List[Path] = []
    for p in out:
        rp = str(Path(p).resolve())
        if rp not in seen:
            seen.add(rp)
            uniq.append(Path(rp))
    return uniq

def _is_under(path: Path, parents: List[Path]) -> bool:
    try:
        rp = path.resolve()
    except Exception:
        rp = path
    for ex in parents:
        try:
            # py>=3.9
            if rp.is_relative_to(ex):
                return True
        except Exception:
            if str(rp).startswith(str(ex)):
                return True
    return False

# -------------------------------
# 규칙 필터
# -------------------------------
class RuleFilter:
    def __init__(self, include_names: List[str], include_exts: Set[str],
                 exclude_dirs: List[Path]) -> None:
        self.include_names = include_names or []
        self.include_exts  = include_exts or set()
        self.exclude_dirs  = exclude_dirs or []

    def match_path(self, p: Path) -> bool:
        # 제외 디렉토리
        if _is_under(p, self.exclude_dirs):
            return False
        name = p.name
        ext = p.suffix[1:].lower() if p.suffix else ""
        # 파일명 글롭
        for pat in self.include_names:
            if glob.fnmatch.fnmatch(name, pat):
                return True
        # 확장자
        return (ext and ext in self.include_exts)

# -------------------------------
# Watchdog 이벤트 기반 모니터
# -------------------------------
def monitor_with_watchdog(cfg_path="coverup_so.json"):
    cfg = load_config(cfg_path)

    watch_dirs     = cfg.get("watch_dirs") or ["~"]  # 경로 하드코딩 X, 사용자/환경에 맞게 확장
    include_names  = cfg.get("include_names") or []
    include_exts   = {_norm_ext(e) for e in (cfg.get("include_exts") or [])}
    exclude_dirs   = _expand_watch_dirs(cfg.get("exclude_dirs") or [])
    quiet_header   = bool(cfg.get("quiet_header", False))

    watch_dirs_expanded = _expand_watch_dirs(watch_dirs)
    if not watch_dirs_expanded:
        print("[!] watch_dirs 에서 감시할 디렉토리를 찾지 못했습니다. (예: ['~', 'C:\\\\Users\\\\*\\\\Downloads'])")
        return

    if not quiet_header:
        print("[*] Cover-up monitoring (OS events via watchdog)...\n")
        for d in watch_dirs_expanded:
            print(f"  - WATCH DIR: {d}")
        if include_names:
            print(f"  - NAME PATTERNS: {include_names}")
        if include_exts:
            print(f"  - EXTENSIONS: {sorted(include_exts)}")
        for d in exclude_dirs:
            print(f"  - EXCLUDE DIR: {d}")
        print()

    # 이벤트 핸들러
    from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent, FileMovedEvent
    from watchdog.observers import Observer

    rule = RuleFilter(include_names, include_exts, exclude_dirs)

    class Handler(FileSystemEventHandler):
        def _log_if_match(self, label: str, path: Path, extra: str = ""):
            if rule.match_path(path):
                print(convention_line(label, dk=str(path), extra=extra))

        def on_created(self, event: FileCreatedEvent):
            p = Path(event.src_path)
            self._log_if_match("File Appeared", p)
            # 필요시 해시/부가정보 출력(선택)
            h = sha256_of(p)
            if h:
                print("[INFO] File Created")
                print(f"- File: {p}\n- Hash: {h}\n- Timestamp: {now_local()}\n")

        def on_deleted(self, event: FileDeletedEvent):
            p = Path(event.src_path)
            self._log_if_match("Cover-up Delete", p)
            print("[ALERT] File Delete Detected")
            print(f"- File: {p}\n- Timestamp: {now_local()}\n")

        def on_modified(self, event: FileModifiedEvent):
            # 디렉토리 수정은 스킵
            if event.is_directory:
                return
            p = Path(event.src_path)
            if rule.match_path(p):
                old_new = ""
                new_h = sha256_of(p)
                if new_h:
                    old_new = f"new={new_h[:12]}"
                print(convention_line("Cover-up Modify", dk=str(p), extra=old_new))
                print("[INFO] File Modified Detected")
                print(f"- File: {p}\n- Hash: {new_h}\n- Timestamp: {now_local()}\n")

        def on_moved(self, event: FileMovedEvent):
            src = Path(event.src_path)
            dst = Path(event.dest_path)
            # src/dst 둘 중 하나라도 규칙에 맞으면 로깅
            src_ok = rule.match_path(src)
            dst_ok = rule.match_path(dst)
            if src_ok or dst_ok:
                extra = f"{src} -> {dst}"
                print(convention_line("Cover-up Move", dk=str(dst), extra=extra))
                print("[INFO] File Moved Detected")
                print(f"- From: {src}\n- To: {dst}\n- Timestamp: {now_local()}\n")

    observer = Observer()
    handler = Handler()

    for d in watch_dirs_expanded:
        observer.schedule(handler, str(d), recursive=True)

    try:
        observer.start()
        # 메인 스레드를 유지
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Cover-up monitoring stopped.")
    finally:
        observer.stop()
        observer.join()

# -------------------------------
if __name__ == "__main__":
    # watchdog 기반 모니터 실행
    try:
        monitor_with_watchdog("coverup_so.json")
    except ModuleNotFoundError:
        print("[!] watchdog 패키지가 필요합니다. 아래 명령으로 설치 후 다시 실행하세요:")
        print("    pip install watchdog")
