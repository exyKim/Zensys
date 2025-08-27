import win32clipboard
import win32con
import time
from datetime import datetime

SENSITIVE_KEYWORDS = ["기밀", "주민번호", "중요", "ask2025"]
BLOCK_MESSAGE = "[Detect Alert] Confidential information detected. Copying is not allowed"
previous_clipboard = ""

print("[*] Real-time Clipboard Monitoring Started...\n")

while True:
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()

            if data != previous_clipboard:
                previous_clipboard = data
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                if any(keyword in data for keyword in SENSITIVE_KEYWORDS):
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()
                    win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, BLOCK_MESSAGE)
                    win32clipboard.CloseClipboard()

                    print("\n[ALERT] Clipboard Keyword Detected")
                    print(f"- Content: {data}")
                    print(f"- Action: Blocked & Replaced")
                    print(f"- Timestamp: {timestamp}")
                else:
                    print(f"[INFO] Clipboard Updated (Safe): {data[:30]}...")

        else:
            win32clipboard.CloseClipboard()

    except Exception as e:
        try:
            win32clipboard.CloseClipboard()
        except:
            pass

    time.sleep(1)
