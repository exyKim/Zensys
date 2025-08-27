import os
import time
import hashlib
import wmi
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_PATHS = [r"C:\sensitiveFile", r"D:\\", r"E:\\", r"F:\\"]  # 감시 대상에 USB 포함
SENSITIVE_KEYWORD = "ask2025"
ALLOWED_USB_SERIALS = ["1234567890ABCDEF"]
recent_deletes = {}
seen_usb_serials = set()

def calculate_hash(path):
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None

def get_connected_usb_serials():
    c = wmi.WMI()
    usb_serials = []
    for disk in c.Win32_DiskDrive():
        if "USB" in disk.InterfaceType:
            serial = disk.PNPDeviceID.split("\\")[-1]
            usb_serials.append((disk.Model, serial))
    return usb_serials

class FileMovementHandler(FileSystemEventHandler):
    def on_deleted(self, event):
        if not event.is_directory and SENSITIVE_KEYWORD in os.path.basename(event.src_path):
            file_name = os.path.basename(event.src_path)
            recent_deletes[file_name] = {
                "path": event.src_path,
                "time": time.time()
            }

    def on_moved(self, event):
        if not event.is_directory and SENSITIVE_KEYWORD in os.path.basename(event.dest_path):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print("\n[ALERT] Sensitive File Drag-and-Drop (Move) Detected")
            print(f"- Type: Move")
            print(f"- File Name: {os.path.basename(event.dest_path)}")
            print(f"- From: {event.src_path}")
            print(f"- To: {event.dest_path}")
            print(f"- Timestamp: {timestamp}")
            if is_usb_path(event.dest_path):
                print("USB Copy Detected")

    def on_created(self, event):
        if not event.is_directory and SENSITIVE_KEYWORD in os.path.basename(event.src_path):
            file_name = os.path.basename(event.src_path)
            file_hash = calculate_hash(event.src_path)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if file_name in recent_deletes:
                src_info = recent_deletes[file_name]
                action_type = "Cut + Paste"
                from_path = src_info["path"]
                del recent_deletes[file_name]
            else:
                action_type = "Copy"
                from_path = "Unknown (assumed copy)"

            print("\n[ALERT] Sensitive File Transfer Detected")
            print(f"- Type: {action_type}")
            print(f"- File Name: {file_name}")
            print(f"- From: {from_path}")
            print(f"- To: {event.src_path}")
            print(f"- File Hash: {file_hash}")
            print(f"- Timestamp: {timestamp}")
            if is_usb_path(event.src_path):
                print("⚠️ USB Copy Detected")

def is_usb_path(path):
    return path.startswith("D:\\") or path.startswith("E:\\") or path.startswith("F:\\")

if __name__ == "__main__":
    observers = []
    handler = FileMovementHandler()

    for path in WATCH_PATHS:
        os.makedirs(path, exist_ok=True)
        observer = Observer()
        observer.schedule(handler, path=path, recursive=True)
        observer.start()
        observers.append(observer)

    print("[*] Monitoring for sensitive file movement and USB connection...\n")

    try:
        while True:
            current_usb_devices = get_connected_usb_serials()
            for model, serial in current_usb_devices:
                if serial not in seen_usb_serials:
                    seen_usb_serials.add(serial)
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if serial in ALLOWED_USB_SERIALS:
                        print(f"[INFO] Registered USB Device Connected\n- Device Name: {model}\n- Serial Number: {serial}\n- Timestamp: {timestamp}")
                    else:
                        print(f"[ALERT] Unregistered USB Device Connected\n- Device Name: {model}\n- Serial Number: {serial}\n- Timestamp: {timestamp}")
            time.sleep(2)
    except KeyboardInterrupt:
        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()
