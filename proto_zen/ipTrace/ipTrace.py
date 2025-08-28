import time
import socket
import psutil
import ipaddress
from datetime import datetime

# -------------------------------
# Config 로더: JSON5(주석 허용) → JSON(주석 제거) 순서로 시도
# -------------------------------
def _strip_line_comments(text: str) -> str:
    import re
    # 아주 단순한 // 주석 제거 (문자열 내부 // 케이스는 운영에서 JSON5 사용 권장)
    return re.sub(r"//.*", "", text)

def load_config(path="ip_so.json") -> dict:
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

def get_hostname() -> str:
    return socket.gethostname()

def get_local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "Unknown"

def is_external_ip(ip: str) -> bool:
    """사설/루프백/링크로컬/멀티캐스트 등은 외부로 보지 않음"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast)
    except ValueError:
        return False

def get_process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

def build_watch_nets(items):
    nets = []
    for item in items or []:
        try:
            if "/" in item:
                nets.append(ipaddress.ip_network(item, strict=False))
            else:
                nets.append(ipaddress.ip_network(item + "/32"))
        except Exception:
            print(f"[WARN] 잘못된 watchlist 항목 무시: {item}")
    return nets

def ip_in_watchlist(ip: str, nets) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return any(ip_obj in net for net in nets)

def convention_line_ip_detect(remote_ip: str, pid: int, proc_name: str) -> str:
    # PDF 컨벤션: [I] "IP Detect Alert" YYYY-MM-DD HH:MM:SS DK='IP' / pid=... proc='...'
    return f"[I] \"IP Detect Alert\" {now_local()} DK='{remote_ip}' / pid={pid} proc='{proc_name}'"

# -------------------------------
# 메인 모니터
# -------------------------------
def monitor_ip_connections(cfg_path="ip_so.json"):
    cfg = load_config(cfg_path)
    watch_nets = build_watch_nets(cfg.get("watchlist", []))

    suspicious_ports = cfg.get("suspicious_ports") or [
        21, 22, 23, 135, 139, 445, 3389, 4444, 8080, 8082, 9001, 1337, 6667
    ]
    scan_interval = float(cfg.get("scan_interval_sec", 3))
    debounce_sec = int(cfg.get("debounce_sec", 10))

    hostname = get_hostname()
    local_ip = get_local_ip()

    # (pid, rip, rport) → last_seen_ts
    seen = {}
    print("[*] Monitoring external IP connections and suspicious ports...\n")
    print(f"[*] Hostname: {hostname}")
    print(f"[*] Local IP: {local_ip}\n")

    try:
        while True:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr or conn.status != psutil.CONN_ESTABLISHED:
                    continue

                r_ip, r_port = conn.raddr.ip, conn.raddr.port
                if not is_external_ip(r_ip):
                    continue

                key = (conn.pid or 0, r_ip, r_port)
                now = time.time()
                # 디바운스: 동일 연결 반복 출력 억제
                if key in seen and (now - seen[key] < debounce_sec):
                    continue
                seen[key] = now

                proc_name = get_process_name(conn.pid or 0)

                # 1) watchlist 매치 시: 컨벤션 한 줄을 "맨 위에" 먼저 출력
                if ip_in_watchlist(r_ip, watch_nets):
                    print(convention_line_ip_detect(r_ip, conn.pid or 0, proc_name))

                # 2) 요약 라벨
                if int(r_port) in suspicious_ports:
                    print("\n[ALERT] Suspicious Port Connection Detected")
                else:
                    print("\n[INFO] External IP Connection Detected")

                # 3) 상세 필드
                print(f"- Hostname: {hostname}")
                print(f"- Local IP: {local_ip}")
                print(f"- Process: {proc_name}")
                print(f"- Remote IP: {r_ip}")
                print(f"- Port: {r_port}")
                print(f"- Timestamp: {now_local()}")

            time.sleep(scan_interval)
    except KeyboardInterrupt:
        print("\n[*] IP monitoring stopped.")

# -------------------------------
if __name__ == "__main__":
    monitor_ip_connections("ip_so.json")
