import psutil
import time
import socket
from datetime import datetime

SUSPICIOUS_PORTS = [
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    135,    # RPC
    139,    # NetBIOS
    445,    # SMB
    3389,   # RDP (원격 데스크톱)
    4444,   # Metasploit 기본 포트
    8080, 8082,  # 웹 프록시, 웹쉘
    9001    # C2 서버 통신 포트
]

PRIVATE_PREFIXES = (
    "10.",
    "192.168.",
    "172.",        # 172.16.0.0 ~ 172.31.255.255 포함
    "127.",        # 루프백 (localhost)
    "169.254."     # APIPA (자동 사설 IP)
)



def is_external_ip(ip):
    return not ip.startswith(PRIVATE_PREFIXES)

def get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

def get_hostname():
    return socket.gethostname()

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"

def monitor_ip_connections():
    seen_connections = set()
    hostname = get_hostname()
    local_ip = get_local_ip()

    print("[*] Monitoring external IP connections and suspicious ports...\n")
    print(f"[*] Hostname: {hostname}")
    print(f"[*] Local IP: {local_ip}\n")

    while True:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.status == psutil.CONN_ESTABLISHED:
                    ip, port = conn.raddr
                    if is_external_ip(ip):
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        key = (conn.pid, ip, port)

                        if key not in seen_connections:
                            seen_connections.add(key)
                            process_name = get_process_name(conn.pid)

                            if port in SUSPICIOUS_PORTS:
                                print("\n[ALERT] Suspicious Port Connection Detected")
                            else:
                                print("\n[INFO] External IP Connection Detected")
                            
                            print(f"- Hostname: {hostname}")
                            print(f"- Local IP: {local_ip}")
                            print(f"- Process: {process_name}")
                            print(f"- Remote IP: {ip}")
                            print(f"- Port: {port}")
                            print(f"- Timestamp: {timestamp}")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[*] IP monitoring stopped.")
            break

if __name__ == "__main__":
    monitor_ip_connections()
