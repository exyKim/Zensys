import os
<<<<<<< HEAD
import time
=======
>>>>>>> fix/usb-lite
import glob
import hashlib
from pathlib import Path
from datetime import datetime
<<<<<<< HEAD
=======
from typing import Optional, Set, List
>>>>>>> fix/usb-lite

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

<<<<<<< HEAD
def sha256_of(p: Path) -> str | None:
=======
def sha256_of(p: Path) -> Optional[str]:
>>>>>>> fix/usb-lite
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

<<<<<<< HEAD
# -------------------------------
# 매칭 규칙
# -------------------------------
=======
>>>>>>> fix/usb-lite
def _norm_ext(e: str) -> str:
    e = e.lower().strip()
    return e[1:] if e.startswith(".") else e

<<<<<<< HEAD
def _expand_watch_dirs(patterns: list[str]) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        # ~, 환경변수, 와일드카드(** 포함) 모두 허용
        exp = os.path.expandvars(os.path.expanduser(pat))
        matches = glob.glob(exp, recursive=True)
        if not matches:
            # 디렉토리가 실제 하나일 수도 있음
=======
def _expand_watch_dirs(patterns: List[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        exp = os.path.expandvars(os.path.expanduser(pat))
        matches = glob.glob(exp, recursive=True)
        if not matches:
>>>>>>> fix/usb-lite
            if os.path.isdir(exp):
                out.append(Path(exp))
        else:
            for m in matches:
                if os.path.isdir(m):
                    out.append(Path(m))
<<<<<<< HEAD
    # 중복 제거
    seen = set()
    uniq = []
    for p in out:
        rp = str(p.resolve())
=======
    # dedupe (realpath)
    seen = set()
    uniq: List[Path] = []
    for p in out:
        rp = str(Path(p).resolve())
>>>>>>> fix/usb-lite
        if rp not in seen:
            seen.add(rp)
            uniq.append(Path(rp))
    return uniq

<<<<<<< HEAD
def _is_excluded(path: Path, exclude_dirs: list[Path]) -> bool:
=======
def _is_under(path: Path, parents: List[Path]) -> bool:
>>>>>>> fix/usb-lite
    try:
        rp = path.resolve()
    except Exception:
        rp = path
<<<<<<< HEAD
    for ex in exclude_dirs:
        try:
            if rp.is_relative_to(ex):
                return True
        except AttributeError:
            # Python < 3.9 호환
            try:
                if str(rp).startswith(str(ex)):
                    return True
            except Exception:
                pass
    return False

def _should_index(file_path: Path, include_names: list[str], include_exts: set[str]) -> bool:
    name = file_path.name
    ext = file_path.suffix[1:].lower() if file_path.suffix else ""
    # 파일명 글롭 매칭
    for pat in include_names:
        if glob.fnmatch.fnmatch(name, pat):
            return True
    # 확장자 매칭
    if ext and ext in include_exts:
        return True
    return False

# -------------------------------
# 메인: 규칙 기반 파일 탐지/감시 (폴링)
# -------------------------------
def monitor_by_rules(cfg_path="coverup_so.json"):
    cfg = load_config(cfg_path)

    watch_dirs = cfg.get("watch_dirs") or ["~"]
    include_names = cfg.get("include_names") or []    # 예: ["audit.*", "export.*"]
    include_exts  = cfg.get("include_exts")  or []    # 예: ["log", "evtx", "csv"]
    exclude_dirs  = cfg.get("exclude_dirs")  or []    # 예: ["C:\\Windows", "/System"]
    scan_interval = float(cfg.get("scan_interval_sec", 2))
    max_files     = int(cfg.get("max_files", 10000))  # 안전장치

    include_exts = {_norm_ext(e) for e in include_exts}
    watch_dirs_expanded = _expand_watch_dirs(watch_dirs)
    exclude_dirs_expanded = _expand_watch_dirs(exclude_dirs)

    if not watch_dirs_expanded:
        print("[!] watch_dirs 에서 감시할 디렉토리를 찾지 못했습니다. (예: ['~', 'C:\\\\Users\\\\*\\\\Desktop'])")
        return

    print("[*] Cover-up monitoring by rules...\n")
    for d in watch_dirs_expanded:
        print(f"  - WATCH DIR: {d}")
    if include_names:
        print(f"  - NAME PATTERNS: {include_names}")
    if include_exts:
        print(f"  - EXTENSIONS: {sorted(include_exts)}")
    if exclude_dirs_expanded:
        for d in exclude_dirs_expanded:
            print(f"  - EXCLUDE DIR: {d}")
    print()

    # 상태: path -> {"exists": bool, "hash": str|None}
    state: dict[Path, dict] = {}

    def _scan_once() -> set[Path]:
        found: set[Path] = set()
        count = 0
        for root in watch_dirs_expanded:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                current_dir = Path(dirpath)
                # 제외 디렉토리는 하위 탐색 자체를 차단
                if _is_excluded(current_dir, exclude_dirs_expanded):
                    dirnames[:] = []  # 하위 탐색 중지
                    continue

                for fn in filenames:
                    if count >= max_files:
                        break
                    fp = current_dir / fn
                    if _should_index(fp, include_names, include_exts):
                        found.add(fp)
                        count += 1
                if count >= max_files:
                    break
            if count >= max_files:
                break
        return found

    # 초기 스캔 (베이스라인)
    current = _scan_once()
    for p in sorted(current):
        h = sha256_of(p)
        state[p] = {"exists": True, "hash": h}
        short = f"(sha256={h[:12]}...)" if h else ""
        print(f"  - FOUND {p} {short}")
    print()

    # 루프
    try:
        while True:
            next_set = _scan_once()

            # 삭제 감지
            for p, prev in list(state.items()):
                if p not in next_set and prev["exists"]:
                    print(convention_line("Cover-up Delete", dk=str(p)))
                    print("[ALERT] File Delete Detected")
                    print(f"- File: {p}")
                    print(f"- Last Known Hash: {prev['hash']}")
                    print(f"- Timestamp: {now_local()}\n")
                    state[p]["exists"] = False
                    state[p]["hash"] = None

            # 신규/수정 감지
            for p in next_set:
                prev = state.get(p)
                if prev and prev["exists"]:
                    new_hash = sha256_of(p)
                    if prev["hash"] and new_hash and new_hash != prev["hash"]:
                        print(convention_line(
                            "Cover-up Modify",
                            dk=str(p),
                            extra=f"old={prev['hash'][:12]} new={new_hash[:12]}"
                        ))
                        print("[INFO] File Modified Detected")
                        print(f"- File: {p}")
                        print(f"- Old Hash: {prev['hash']}")
                        print(f"- New Hash: {new_hash}")
                        print(f"- Timestamp: {now_local()}\n")
                        prev["hash"] = new_hash
                else:
                    # 새로 발견
                    new_hash = sha256_of(p)
                    state[p] = {"exists": True, "hash": new_hash}
                    print(convention_line("File Appeared", dk=str(p)))
                    print("[INFO] File Exists (baseline set)")
                    print(f"- File: {p}")
                    print(f"- Hash: {new_hash}")
                    print(f"- Timestamp: {now_local()}\n")

            time.sleep(scan_interval)
    except KeyboardInterrupt:
        print("\n[*] Cover-up monitoring stopped.")

# -------------------------------
if __name__ == "__main__":
    monitor_by_rules("coverup_so.json")
=======
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
>>>>>>> fix/usb-lite
