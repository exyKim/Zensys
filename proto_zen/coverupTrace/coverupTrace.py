import time
import hashlib
from pathlib import Path
from datetime import datetime

# -------------------------------
# Config 로더 (json5 지원 실패 시 주석 제거 후 json 파싱)
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

def sha256_of(p: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def convention_line(text: str, dk: str, extra: str = "") -> str:
    # Zensys 컨벤션 (ipTrace 느낌): [C] "..." YYYY-MM-DD HH:MM:SS DK='...' / ...
    tail = f" / {extra}" if extra else ""
    return f"[C] \"{text}\" {now_local()} DK='{dk}'{tail}"

# -------------------------------
# 메인: 등록 파일 수정/삭제 감시 (폴링)
# -------------------------------
def monitor_registered_files(cfg_path="coverup_so.json"):
    cfg = load_config(cfg_path)
    file_list = [Path(p) for p in (cfg.get("files") or [])]
    scan_interval = float(cfg.get("scan_interval_sec", 2))

    if not file_list:
        print("[!] coverup_so.json 의 files 항목에 감시할 파일 경로를 넣어주세요.")
        return

    # 베이스라인: 존재하면 해시 저장
    state = {}  # path -> {"exists": bool, "hash": str|None}
    print("[*] Monitoring registered files for modify/delete...\n")
    for p in file_list:
        exists = p.exists()
        h = sha256_of(p) if exists else None
        state[p] = {"exists": exists, "hash": h}
        print(f"  - {'FOUND ' if exists else 'MISSING'} {p} "
              f"{'(sha256=' + h[:12] + '...)' if h else ''}")
    print()

    try:
        while True:
            for p in file_list:
                prev = state[p]
                exists = p.exists()

                if exists:
                    # 수정 여부(내용 해시 변경) 확인
                    new_hash = sha256_of(p)
                    if prev["exists"] and prev["hash"] and new_hash and new_hash != prev["hash"]:
                        # 수정 감지
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
                        # 상태 갱신
                        state[p]["hash"] = new_hash
                        state[p]["exists"] = True

                    # 처음 발견(기존에 없었는데 생김) → 이번 프로토타입에선 ‘등록/복구’로만 출력
                    elif not prev["exists"]:
                        print(convention_line("File Appeared", dk=str(p)))
                        print("[INFO] File Exists (baseline set)")
                        print(f"- File: {p}")
                        print(f"- Hash: {new_hash}")
                        print(f"- Timestamp: {now_local()}\n")
                        state[p]["exists"] = True
                        state[p]["hash"] = new_hash

                else:
                    # 삭제 감지
                    if prev["exists"]:
                        print(convention_line("Cover-up Delete", dk=str(p)))
                        print("[ALERT] File Delete Detected")
                        print(f"- File: {p}")
                        print(f"- Last Known Hash: {prev['hash']}")
                        print(f"- Timestamp: {now_local()}\n")
                        state[p]["exists"] = False
                        state[p]["hash"] = None

            time.sleep(scan_interval)
    except KeyboardInterrupt:
        print("\n[*] Cover-up monitoring stopped.")

# -------------------------------
if __name__ == "__main__":
    monitor_registered_files("coverup_so.json")