import win32clipboard
import win32con
import time
import json5
from datetime import datetime

POLICY_PATH = "cb_so.json"

def load_policy(path=POLICY_PATH):
    with open(path, "r", encoding="utf-8") as f:
        return json5.load(f)

def main():
    cfg = load_policy()
    keywords = cfg["clipboard"]["sensitive_keywords"]
    block_msg = cfg["clipboard"]["block_message"]
    scan_iv = cfg["clipboard"].get("scan_interval_sec", 1)

    prev_clipboard = ""
    print("[*] Real-time Clipboard Monitoring Started...\n")

    while True:
        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()

                if data != prev_clipboard:
                    prev_clipboard = data
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    if any(keyword in data for keyword in keywords):
                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, block_msg)
                        win32clipboard.CloseClipboard()

                        # 젠시스 로그
                        print(f"[B] \"Clipboard Detect Alert\" {ts} DK='{data[:15]}...' / action=blocked")

                    else:
                        print(f"[INFO] Clipboard Updated (Safe): {data[:30]}...")

            else:
                win32clipboard.CloseClipboard()

        except Exception as e:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass

        time.sleep(scan_iv)

if __name__ == "__main__":
    main()
