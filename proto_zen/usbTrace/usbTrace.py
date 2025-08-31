import time
import re
import json
import platform
from pathlib import Path
from datetime import datetime

IS_WINDOWS = platform.system().lower().startswith("win")
if IS_WINDOWS:
    import pythoncom  # pip install pywin32
    import wmi        # pip install wmi

# -----------------------
# JSON 로더 (json5 주석 허용)
# -----------------------
def _strip_line_comments(text: str) -> str:
    return re.sub(r"//.*", "", text)

def load_config(path="usb_so.json") -> dict:
    try:
        import json5
        with open(path, "r", encoding="utf-8") as f:
            return json5.load(f)
    except Exception:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        return json.loads(_strip_line_comments(raw))

# -----------------------
# 로깅/포맷터 (콘솔 + 파일 동시)
# -----------------------
LOG_FILE: Path | None = None

def init_logger(path_str: str | None):
    global LOG_FILE
    if path_str:
        p = Path(path_str)
        p.parent.mkdir(parents=True, exist_ok=True)
        LOG_FILE = p
    else:
        LOG_FILE = None

def _write_log(line: str):
    if LOG_FILE:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

def now_local() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def line(signature: str, text: str, dk: str, extra: str = "") -> str:
    tail = f" / {extra}" if extra else ""
    return f"[{signature}] \"{text}\" {now_local()} DK='{dk}'{tail}"

def emit(signature: str, text: str, dk: str, extra: str = ""):
    s = line(signature, text, dk, extra)
    print(s); _write_log(s)

def plog(msg: str):
    print(msg); _write_log(msg)

# -----------------------
# 유틸
# -----------------------
VID_RE = re.compile(r"VID_([0-9A-F]{4})", re.I)
PID_RE = re.compile(r"PID_([0-9A-F]{4})", re.I)

def parse_vid_pid_serial(pnp_id: str) -> tuple[str | None, str | None, str | None]:
    """USBSTOR, HID 등 다양한 PNPDeviceID에서 최대한 VID/PID/Serial을 추출."""
    vid = (VID_RE.search(pnp_id).group(1) if VID_RE.search(pnp_id) else None)
    pid = (PID_RE.search(pnp_id).group(1) if PID_RE.search(pnp_id) else None)
    serial = None
    if "\\" in pnp_id:
        token = pnp_id.split("\\")[-1]
        serial = token.split("&")[0] if token else None
    return vid, pid, serial

def make_uid(vendor_id: str | None, product_id: str | None, serial: str | None) -> str:
    v = (vendor_id or "UNKNOWN").upper()
    p = (product_id or "UNKNOWN").upper()
    s = (serial or "NOSERIAL").upper()
    return f"{v}:{p}:{s}"

def human_bytes(n: int | None) -> str:
    if not n: return "-"
    for unit in ["B","KB","MB","GB","TB","PB"]:
        if n < 1024: return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}EB"

# -----------------------
# 현재 연결된 USB 저장장치 스냅샷(윈도우)
# -----------------------
def list_usb_windows() -> list[dict]:
    pythoncom.CoInitialize()
    try:
        conn = wmi.WMI()
        out = []
        for disk in conn.Win32_DiskDrive(InterfaceType="USB"):
            pnp_id = disk.PNPDeviceID or ""
            vid, pid, serial = parse_vid_pid_serial(pnp_id)

            mount, fs, label = None, None, None
            try:
                for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for ld in part.associators("Win32_LogicalDiskToPartition"):
                        mount = getattr(ld, "DeviceID", None)   # 'E:'
                        fs    = getattr(ld, "FileSystem", None) # 'NTFS'
                        label = getattr(ld, "VolumeName", None) # 'SANDISK'
                        break
            except Exception:
                pass

            size = None
            try:
                size = int(disk.Size) if disk.Size is not None else None
            except Exception:
                pass

            uid = make_uid(vid, pid, serial)
            out.append({
                "uid": uid,
                "vendor_id": (vid or "UNKNOWN").upper(),
                "product_id": (pid or "UNKNOWN").upper(),
                "serial": (serial or "NOSERIAL").upper(),
                "model": getattr(disk, "Model", None),
                "size_bytes": size,
                "filesystem": fs,
                "volume_label": label,
                "mount_letter": mount,
                "pnp_id": pnp_id,
            })
        return out
    finally:
        pythoncom.CoUninitialize()

def list_usb() -> list[dict]:
    if not IS_WINDOWS:
        return []
    return list_usb_windows()

# -----------------------
# 승인 여부 (우선순위: uid > serial > vendor > product) + 정규화
# -----------------------
def _norm(s: str | None) -> str:
    return (s or "").strip().upper()

def is_approved(dev: dict, cfg: dict) -> tuple[bool, str | None]:
    allow = cfg.get("approved", {})
    uid_whitelist    = {_norm(u) for u in allow.get("uids", [])}
    serial_whitelist = {_norm(s) for s in allow.get("serials", [])}
    vid_whitelist    = {_norm(v) for v in allow.get("vendors", [])}
    pid_whitelist    = {_norm(p) for p in allow.get("products", [])}

    uid    = _norm(dev.get("uid"))
    serial = _norm(dev.get("serial"))
    vid    = _norm(dev.get("vendor_id"))
    pid    = _norm(dev.get("product_id"))

    if uid in uid_whitelist:       return True, "uid"
    if serial in serial_whitelist: return True, "serial"
    if vid in vid_whitelist:       return True, "vendor"
    if pid in pid_whitelist:       return True, "product"
    return False, None

# -----------------------
# 메인 모니터 루프
# -----------------------
def monitor(cfg_path="usb_so.json"):
    if not IS_WINDOWS:
        print("[!] Windows 전용 모니터입니다. (현재 OS 비지원)")
        return

    cfg_file = Path(cfg_path)

    def load():
        cfg = load_config(str(cfg_file))
        print(f"[cfg] loaded: {cfg_file.resolve()}")
        ap = cfg.get("approved", {})
        print(f"[cfg] counts  uids={len(ap.get('uids', []))}  serials={len(ap.get('serials', []))}  "
              f"vendors={len(ap.get('vendors', []))}  products={len(ap.get('products', []))}\n")
        return cfg

    cfg = load()
    cfg_mtime = cfg_file.stat().st_mtime if cfg_file.exists() else 0
    init_logger(cfg.get("log_file", "usb_lite.log"))
    interval = float(cfg.get("scan_interval_sec", 2))

    print("[*] USB Monitor (no DB/server) — Ctrl+C to stop\n")

    prev = {}                 # uid -> last snapshot (dict)
    approved_state = {}       # uid -> bool (현재 승인 여부)

    # 핫 리로드: json 저장되면 즉시 재적용 + 상태변경 알림
    def maybe_reload():
        nonlocal cfg, cfg_mtime, approved_state, prev
        try:
            mt = cfg_file.stat().st_mtime
        except FileNotFoundError:
            return
        if mt != cfg_mtime:
            cfg_mtime = mt
            cfg = load()
            init_logger(cfg.get("log_file", "usb_lite.log"))
            # 이미 꽂혀있는 장치들의 승인 상태 재평가
            for uid, dev in list(prev.items()):
                ok_new, reason_new = is_approved(dev, cfg)
                ok_old = approved_state.get(uid)
                if ok_old is None or ok_new != ok_old:
                    dk = f"uid={uid} mount={dev.get('mount_letter') or '-'}"
                    if ok_new:
                        emit("U", "Policy Update: USB Approved", dk, extra=f"by={reason_new}")
                    else:
                        emit("U", "Policy Update: USB Blocked", dk, extra="unregistered (no match)")
                    approved_state[uid] = ok_new

    # 초기 스냅샷
    devices = list_usb()
    if not devices:
        print("현재 연결된 USB 없음.\n")
    else:
        print("== 현재 연결된 USB ==")
        for d in devices:
            ok, reason = is_approved(d, cfg)
            status = f"APPROVED({reason})" if ok else "UNREGISTERED"
            print(f"- {d['model'] or ''}  |  {d['uid']}  |  {d['mount_letter'] or '-'}  "
                  f"|  {d['filesystem'] or '-'}  |  {human_bytes(d['size_bytes'])}  |  {status}")
            print(f"  PNP={d.get('pnp_id','-')}")
            prev[d["uid"]] = d
            approved_state[d["uid"]] = ok
        print("")

    try:
        while True:
            maybe_reload()

            cur_map = {d["uid"]: d for d in list_usb()}

            # 새로 연결
            for uid, d in cur_map.items():
                if uid not in prev:
                    ok, reason = is_approved(d, cfg)
                    dk = f"uid={uid} mount={d['mount_letter'] or '-'}"
                    emit("U", "USB Connected", dk,
                         extra=f"model={d['model'] or '-'} fs={d['filesystem'] or '-'} "
                               f"size={human_bytes(d['size_bytes'])} approved={reason or 'no'}")
                    if d.get("pnp_id"):
                        print(f"PNP={d['pnp_id']}")
                    # 승인/차단 즉시 안내
                    if ok:
                        emit("U", "USB Approved", dk, extra=f"by={reason}")
                    else:
                        emit("U", "USB Blocked", dk, extra="unregistered (no match)")
                        if d['serial'] != "NOSERIAL":
                            plog(f"  승인 예시(serial):  usb_so.json ⇒ approved.serials 에 \"{d['serial']}\" 추가")
                        plog(f"  승인 예시(uid):      usb_so.json ⇒ approved.uids 에 \"{d['uid']}\" 추가")
                        plog("  (주의: 위 문자열은 usb_so.json 파일에 붙여넣으세요. 터미널에 붙여넣지 마세요.)")

                    prev[uid] = d
                    approved_state[uid] = ok

            # 분리됨
            for uid, d0 in list(prev.items()):
                if uid not in cur_map:
                    dk = f"uid={uid} mount={d0.get('mount_letter') or '-'}"
                    emit("U", "USB Disconnected", dk, extra=f"model={d0.get('model') or '-'}")
                    del prev[uid]
                    approved_state.pop(uid, None)

            # 속성 변경
            for uid, d in cur_map.items():
                if uid in prev:
                    p = prev[uid]
                    changed = []
                    for k in ("mount_letter", "filesystem", "volume_label"):
                        if (p.get(k) or "-") != (d.get(k) or "-"):
                            changed.append(f"{k}:{p.get(k) or '-'}→{d.get(k) or '-'}")
                    if changed:
                        dk = f"uid={uid} mount={d['mount_letter'] or '-'}"
                        emit("I", "USB Meta Updated", dk, extra="; ".join(changed))
                        prev[uid] = d

            time.sleep(interval)
    except KeyboardInterrupt:
        plog("\n[*] Stopped.")

# -----------------------
if __name__ == "__main__":
    monitor("usb_so.json")