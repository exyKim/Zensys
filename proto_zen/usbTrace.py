import os
import re
import sys
import time
import json
import base64
import threading
import platform
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List

# ---------------------------
# OS/WMI 준비
# ---------------------------
IS_WINDOWS = platform.system().lower().startswith("win")
if IS_WINDOWS:
    import pythoncom  # type: ignore
    import wmi  # pip install wmi pywin32

# ---------------------------
# 설정값
# ---------------------------
DB_URL = os.environ.get("USB_DB_URL", "sqlite:///./usb.db")
LOG_FILE = Path(os.environ.get("ZEN_LOG_FILE", "./forensic.log"))
POLL_SEC = float(os.environ.get("USB_POLL_SEC", "2.0"))
DEFAULT_USER = os.environ.get("ZEN_USER", None)

# ---------------------------
# DB 스키마(테이블설계 + 연결 설정)
# ---------------------------
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, create_engine, ForeignKey, BigInteger
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})    #DB(usv.db)랑 연결
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class USBDevice(Base):
    __tablename__ = "usb_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String, unique=True, index=True)                 # VID:PID:SERIAL (장치 고유값)
    model = Column(String, nullable=True)                         # model/vendor_id/product_id/serial 은 장치정보
    vendor_id = Column(String, index=True)
    product_id = Column(String, index=True)                       # vendor_id= 제조사 식별 4자리 코드(제조사) /product_id= 제품 식별 4자리 코드(제품/모델) / Ex) 0781=샌디스크 ,05AC=애플,04E8=삼성
    serial = Column(String, index=True)
    size_bytes = Column(BigInteger, nullable=True)                # size_bytes, filesystem, volume_label, mount_letter: 용량/파일시스템/볼륨명/드라이브문자(E: 등)
    filesystem = Column(String, nullable=True)
    volume_label = Column(String, nullable=True)
    mount_letter = Column(String, nullable=True)
    status = Column(String, default="pending", index=True)       # approved | blocked | pending
    owner = Column(String, nullable=True)
    security_level = Column(String, nullable=True)               # 보안등급
    register_reason = Column(String, nullable=True)              # 등록사유
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))   # 최초 확인 시간
    last_seen  = Column(DateTime, default=lambda: datetime.now(timezone.utc))   # 마지막 확인 시간
    connected = Column(Boolean, default=False)                      # 현재 연결 상태

    events = relationship("USBEvent", back_populates="device", cascade="all, delete-orphan")    #usb장치 하나에 여러개 이벤트를 가질수있게 연결하는 것

class USBEvent(Base):
    __tablename__ = "usb_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("usb_devices.id"))
    event_type = Column(String)                                   # connected | disconnected | registered | blocked | updated
    detail = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    device = relationship("USBDevice", back_populates="events")

Base.metadata.create_all(bind=engine)

# ---------------------------
# 유틸: UID/사용자/로그
# ---------------------------
VIDPID_SERIAL_RE = re.compile(r"VID_([0-9A-F]{4}).*PID_([0-9A-F]{4}).*\\([^\\]+)$", re.IGNORECASE)      # 문자열에서 VID(제조사),PID(제품),시리얼 뽑아내는 정규식

def make_usb_uid(vendor_id: str, product_id: str, serial: str) -> str:  #3개의 문자열을 받아서 합쳐서 Uid 생성 (vid+pid+serial)
    return f"{vendor_id.upper()}:{product_id.upper()}:{serial.upper()}"

def resolve_user() -> str:      #현재 로그인한 사용자 이름을 반환, 실패시 DEFAULT_USER 또는 "unknown" 반환
    try:
        return DEFAULT_USER or os.getlogin()
    except Exception:
        return DEFAULT_USER or "unknown"

def emit_detection_log(signature: str, alert_text: str, dk_value: str, user: Optional[str] = None):  #로그를 한줄로 기록(시그니처: [U]Usb모듈,alertText: 읽기쉬운 메시지 , DK(Detect Keyword) :핵심 식별 정보(예: uid, 드라이브 문자) )
    date_str = datetime.now().strftime("%Y-%m-%d")
    date_str = datetime.now().strftime("%Y-%m-%d")
    user_name = user or resolve_user()
    line = f"{signature} \"{alert_text}\" {date_str} DK '{dk_value}' / user '{user_name}'"
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)

_event_listeners: List = []     # 이벤트 리스너 콜백 함수 목록 (USB 이벤트 발생 시 호출됨)

def on_event(cb):
    _event_listeners.append(cb)
    return cb


def record_event(db, device: USBDevice, event_type: str, detail: Optional[str] = None): #USB 이벤트 기록 및 알림
    ev = USBEvent(device_id=device.id, event_type=event_type, detail=detail)
    db.add(ev)
    db.commit()

    dk = f"uid={device.uid}"
    if device.mount_letter:
        dk += f" mount={device.mount_letter}"
    if device.status:
        dk += f" status={device.status}"
    emit_detection_log("U", f"USB {event_type.capitalize()}", dk)

    # notify listeners (console/WS/UI)
    for cb in list(_event_listeners):
        try:
            cb(device, event_type, detail)
        except Exception:
            pass

# ---------------------------
# WMI로 USB 저장장치 스냅샷
# ---------------------------

def list_usb_storage_windows() -> List[dict]:   #현재 연결된 USB 저장장치 목록을 딕셔너리 리스트로 반환(Windows 전용)
    pythoncom.CoInitialize()
    try:
        conn = wmi.WMI()
        devices = []
        for disk in conn.Win32_DiskDrive(InterfaceType="USB"):
            pnp_id = disk.PNPDeviceID or ""  # 예: 'USB\\VID_0781&PID_5583\\AA0102...'
            m = VIDPID_SERIAL_RE.search(pnp_id)
            vendor_id, product_id, serial = (None, None, None)
            if m:
                vendor_id, product_id, serial = m.group(1), m.group(2), m.group(3)

            size_bytes = None
            try:
                size_bytes = int(disk.Size) if disk.Size is not None else None
            except Exception:
                pass
            # 파티션 -> 논리디스크 매핑으로 드라이브(E:)/파일시스템(NTFS)/볼륨라벨 획득
            #결과 예시: {model, vendor_id, product_id, serial, size_bytes, filesystem, volume_label, mount_letter}          
            mount_letter = None
            filesystem = None
            volume_label = None
            try:
                for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for ld in part.associators("Win32_LogicalDiskToPartition"):
                        mount_letter = getattr(ld, "DeviceID", None)  # 'E:'
                        filesystem = getattr(ld, "FileSystem", None)
                        volume_label = getattr(ld, "VolumeName", None)
                        break
            except Exception:
                pass

            devices.append({
                "model": getattr(disk, "Model", None),
                "vendor_id": vendor_id,
                "product_id": product_id,
                "serial": serial,
                "size_bytes": size_bytes,
                "filesystem": filesystem,
                "volume_label": volume_label,
                "mount_letter": mount_letter,
            })
        return devices
    finally:
        pythoncom.CoUninitialize()


def list_usb_storage() -> List[dict]:
    if not IS_WINDOWS:
        return []
    return list_usb_storage_windows()

# ---------------------------
# 모니터 스레드(주기 스캔)
# ---------------------------
stop_flag = threading.Event()

def monitor_loop():     #백그라운드 스레드에서 주기적으로 USB 장치 스캔 및 DB 갱신
    while not stop_flag.is_set():
        try:
            db = SessionLocal()
            seen_uids = set()

            # 1) 현재 연결된 USB들 스냅샷
            for info in list_usb_storage():
                vendor_id = (info.get("vendor_id") or "").upper()
                product_id = (info.get("product_id") or "").upper()
                serial    = (info.get("serial") or "").upper()
                if not serial:
                    continue  # 식별 핵심 값이 없으면 스킵
                vendor_id = (vendor_id or "UNKNOWN").upper()
                product_id = (product_id or "UNKNOWN").upper()
                
                usb_uid = make_usb_uid(vendor_id, product_id, serial)
                seen_uids.add(usb_uid)

                dev = db.query(USBDevice).filter(USBDevice.uid == usb_uid).first()
                now = datetime.now(timezone.utc)

                if not dev:
                    # 신규 장치(미등록 → pending)
                    dev = USBDevice(
                        uid=usb_uid,
                        model=info.get("model"),
                        vendor_id=vendor_id, product_id=product_id, serial=serial,
                        size_bytes=info.get("size_bytes"),
                        filesystem=info.get("filesystem"),
                        volume_label=info.get("volume_label"),
                        mount_letter=info.get("mount_letter"),
                        status="pending",
                        connected=True,
                        first_seen=now, last_seen=now,
                    )
                    db.add(dev)
                    db.commit()
                    record_event(db, dev, "connected", f"first_seen; mount={dev.mount_letter}")
                else:
                    # 기존 장치 메타 갱신 + 연결 표시
                    dev.model = info.get("model") or dev.model
                    dev.size_bytes = info.get("size_bytes") or dev.size_bytes
                    dev.filesystem = info.get("filesystem") or dev.filesystem
                    dev.volume_label = info.get("volume_label") or dev.volume_label
                    dev.mount_letter = info.get("mount_letter") or dev.mount_letter
                    was_connected = dev.connected
                    dev.connected = True
                    dev.last_seen = now
                    db.commit()
                    if not was_connected:
                        record_event(db, dev, "connected", f"mount={dev.mount_letter}")

            # 2) 이번 스캔에서 보이지 않으면 disconnect 처리
            for dev in db.query(USBDevice).filter(USBDevice.connected.is_(True)).all():
                if dev.uid not in seen_uids:
                    dev.connected = False
                    dev.last_seen = datetime.now(timezone.utc)
                    db.commit()
                    record_event(db, dev, "disconnected", None)

            db.close()
        except Exception as e:
            print(f"[monitor] error: {e}")
        finally:
            stop_flag.wait(POLL_SEC)

# ---------------------------
# (선택) FastAPI — 필요할 때만 불러오기
# ---------------------------

def try_import_fastapi():
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.responses import HTMLResponse, RedirectResponse
        from pydantic import BaseModel, Field
        from typing import List as _List
        return {
            "FastAPI": FastAPI,
            "HTTPException": HTTPException,
            "Query": Query,
            "HTMLResponse": HTMLResponse,
            "RedirectResponse": RedirectResponse,
            "BaseModel": BaseModel,
            "Field": Field,
            "List": _List,
        }
    except Exception:
        return None

FA = try_import_fastapi()

if FA:
    FastAPI = FA["FastAPI"]; HTTPException = FA["HTTPException"]; Query = FA["Query"]
    HTMLResponse = FA["HTMLResponse"]; RedirectResponse = FA["RedirectResponse"]
    BaseModel = FA["BaseModel"]; Field = FA["Field"]; _List = FA["List"]

    # ---------- Pydantic DTO ----------
    class RegisterRequest(BaseModel):
        serial: str = Field(..., description="USB 물리 시리얼(대소문자 무시)")
        device_name: Optional[str] = Field(None, description="표시용 이름(모델과 별도)")
        owner: Optional[str] = None
        security_level: Optional[str] = None
        reason: Optional[str] = None

    class BlockRequest(BaseModel):
        serial: str

    class UpdateMetaRequest(BaseModel):
        serial: str
        owner: Optional[str] = None
        security_level: Optional[str] = None

    class DeviceDTO(BaseModel):
        id: int; uid: str
        model: Optional[str]; vendor_id: Optional[str]; product_id: Optional[str]
        serial: Optional[str]; size_bytes: Optional[int]
        filesystem: Optional[str]; volume_label: Optional[str]; mount_letter: Optional[str]
        status: str; owner: Optional[str]; security_level: Optional[str]
        register_reason: Optional[str]
        first_seen: datetime; last_seen: datetime; connected: bool
        class Config:
            from_attributes = True

    class EventDTO(BaseModel):
        id: int; device_id: int; event_type: str
        detail: Optional[str]; created_at: datetime
        class Config:
            from_attributes = True

    def to_device_dto(device: USBDevice) -> DeviceDTO:
        return DeviceDTO.model_construct(**{
            "id": device.id,
            "uid": device.uid,
            "model": device.model,
            "vendor_id": device.vendor_id,
            "product_id": device.product_id,
            "serial": device.serial,
            "size_bytes": device.size_bytes,
            "filesystem": device.filesystem,
            "volume_label": device.volume_label,
            "mount_letter": device.mount_letter,
            "status": device.status,
            "owner": device.owner,
            "security_level": device.security_level,
            "register_reason": device.register_reason,
            "first_seen": device.first_seen,
            "last_seen": device.last_seen,
            "connected": device.connected,
        })

    # ---------- Web UI (외부 HTML 로드) ----------
    # 작은 Zensys 로고 (SVG). 이 값은 UI의 {{ZLOGO}} 토큰에 주입됨.
    ZENSYS_SVG = (
        "<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'>"
        "<path d='M12 2l7 4v6c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6l7-4z'></path>"
        "<path d='M7 16l10-8M7 12h10'></path>"  # shield with stylized Z
        "</svg>"
    )
    ZENSYS_DATA_URL = "data:image/svg+xml;base64," + base64.b64encode(ZENSYS_SVG.encode("utf-8")).decode("ascii")

    def render_ui():
        """Load external HTML and inject ZLOGO placeholder."""
        try:
            base_dir = Path(__file__).resolve().parent
            ui_path = base_dir / "ui" / "index.html"
            html = ui_path.read_text(encoding="utf-8")
        except Exception as e:
            return f"<h1>UI file not found</h1><p>{e}</p>"
        return html.replace("{{ZLOGO}}", ZENSYS_DATA_URL)

    def create_app():
        app = FastAPI(title="USB Registration Backend (Convention)", version="1.2.1")

        @app.get("/", response_class=RedirectResponse)
        def root():
            return RedirectResponse(url="/ui")

        @app.get("/ui", response_class=HTMLResponse)
        def ui():
            return HTMLResponse(render_ui())

        @app.on_event("startup")
        def on_start():
            if IS_WINDOWS:
                t = threading.Thread(target=monitor_loop, daemon=True)
                t.start()
                emit_detection_log("T", "Service Startup", "usb_monitor=started")
            else:
                print("[*] Non-Windows: monitor disabled")

        @app.on_event("shutdown")
        def on_stop():
            stop_flag.set()
            emit_detection_log("T", "Service Shutdown", "usb_monitor=stopped")

        # ---- API: 장치/이벤트/등록/차단 ----
        @app.get("/devices", response_model=_List[DeviceDTO])
        def list_devices(status: Optional[str] = Query(None), connected: Optional[bool] = Query(None), q: Optional[str] = Query(None)):
            db = SessionLocal(); qry = db.query(USBDevice)
            if status: qry = qry.filter(USBDevice.status == status)
            if connected is not None: qry = qry.filter(USBDevice.connected.is_(connected))
            if q:
                like = f"%{q}%"
                qry = qry.filter((USBDevice.model.ilike(like)) | (USBDevice.serial.ilike(like)) | (USBDevice.uid.ilike(like)))
            items = [to_device_dto(d) for d in qry.order_by(USBDevice.last_seen.desc()).all()]
            db.close(); return items

        @app.get("/devices/{device_id}", response_model=DeviceDTO)
        def get_device(device_id: int):
            db = SessionLocal(); dev = db.query(USBDevice).get(device_id); db.close()
            if not dev: raise HTTPException(404, "device not found")
            return to_device_dto(dev)

        class _Reg(RegisterRequest):
            pass

        @app.post("/devices/register", response_model=DeviceDTO)                
        def register_device(req: _Reg):
            db = SessionLocal(); serial = req.serial.upper(); dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()
            if not dev:
                usb_uid = make_usb_uid("UNKNOWN", "UNKNOWN", serial)
                dev = USBDevice(uid=usb_uid, serial=serial, status="approved", owner=req.owner, security_level=req.security_level, register_reason=req.reason, model=req.device_name)
                db.add(dev); db.commit(); record_event(db, dev, "registered", "pre-registered")
            else:
                dev.status = "approved"; dev.owner = req.owner or dev.owner; dev.security_level = req.security_level or dev.security_level; dev.register_reason = req.reason or dev.register_reason
                if req.device_name: dev.model = req.device_name
                db.commit(); record_event(db, dev, "registered", "approved")
            dto = to_device_dto(dev); db.close(); return dto

        @app.post("/devices/block", response_model=DeviceDTO)               
        def block_device(req: BlockRequest):
            db = SessionLocal(); serial = req.serial.upper(); dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()
            if not dev: raise HTTPException(404, "device not found")
            dev.status = "blocked"; db.commit(); record_event(db, dev, "blocked", None)
            dto = to_device_dto(dev); db.close(); return dto

        @app.post("/devices/update-meta", response_model=DeviceDTO)
        def update_meta(req: UpdateMetaRequest):
            db = SessionLocal(); serial = req.serial.upper(); dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()
            if not dev: raise HTTPException(404, "device not found")
            if req.owner is not None: dev.owner = req.owner
            if req.security_level is not None: dev.security_level = req.security_level
            db.commit(); record_event(db, dev, "updated", "meta updated")
            dto = to_device_dto(dev); db.close(); return dto

        @app.get("/events", response_model=_List[EventDTO])
        def list_events(limit: int = 200):
            db = SessionLocal(); items = db.query(USBEvent).order_by(USBEvent.id.desc()).limit(limit).all()
            out = [EventDTO.model_construct(**{"id": e.id, "device_id": e.device_id, "event_type": e.event_type, "detail": e.detail, "created_at": e.created_at}) for e in items]
            db.close(); return out

        @app.post("/rescan")
        def rescan_now():
            if not IS_WINDOWS:
                emit_detection_log("T", "Rescan Skipped", "platform=non-windows"); return {"ok": True, "found": 0}
            db = SessionLocal(); found = 0
            for info in list_usb_storage():
                vendor_id = (info.get("vendor_id") or "").upper()
                product_id = (info.get("product_id") or "").upper()
                serial    = (info.get("serial") or "").upper()
                if not (vendor_id and product_id and serial):
                    continue
                usb_uid = make_usb_uid(vendor_id, product_id, serial)
                dev = db.query(USBDevice).filter(USBDevice.uid == usb_uid).first()
                now = datetime.now(timezone.utc)
                if not dev:
                    dev = USBDevice(uid=usb_uid, model=info.get("model"), vendor_id=vendor_id, product_id=product_id, serial=serial, size_bytes=info.get("size_bytes"), filesystem=info.get("filesystem"), volume_label=info.get("volume_label"), mount_letter=info.get("mount_letter"), status="pending", connected=True, first_seen=now, last_seen=now)
                    db.add(dev); db.commit(); record_event(db, dev, "connected", "rescan"); found += 1
                else:
                    dev.connected = True; dev.last_seen = now; db.commit()
            db.close(); emit_detection_log("T", "Rescan Finished", f"found={found}"); return {"ok": True, "found": found}

        return app
else:
    # FastAPI 미설치 시에도 파일을 import/run 가능하도록 DTO 없는 더미 함수만 정의
    def create_app():
        raise RuntimeError("FastAPI가 설치되어 있지 않습니다. API를 쓰려면 `pip install fastapi uvicorn pydantic`.")

# ---------------------------
# 콘솔 모드 유틸 (서버 없이)
# ---------------------------

def print_approved_list():
    db = SessionLocal()
    rows = db.query(USBDevice).filter(USBDevice.status == "approved").order_by(USBDevice.last_seen.desc()).all()
    print("\n== 등록된(approved) USB 목록 ==")
    if not rows:
        print("(등록된 장치가 없습니다)")
    for d in rows:
        print(f"- {d.model or ''} | UID={d.uid} | 소유자={d.owner or ''} | 보안등급={d.security_level or ''} | 마운트={d.mount_letter or ''}")
    db.close()


# ---------------------------
# 실행 엔트리포인트
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="USB registration/monitor tool")
    parser.add_argument("--api", action="store_true", help="FastAPI 서버를 실행합니다 (/ui 포함)")
    parser.add_argument("--port", type=int, default=8000, help="API 포트")
    parser.add_argument("--print-approved", action="store_true", help="등록된 목록 먼저 한 번 출력")
    parser.add_argument("--once", action="store_true", help="현재 연결된 USB만 1회 스냅샷 후 종료")
    args = parser.parse_args()

    if args.once:
        # 1회 스냅샷만
        db = SessionLocal(); found = 0
        for info in list_usb_storage():
            vendor_id = (info.get("vendor_id") or "").upper(); product_id = (info.get("product_id") or "").upper(); serial = (info.get("serial") or "").upper()
            if not (vendor_id and product_id and serial):
                continue
            usb_uid = make_usb_uid(vendor_id, product_id, serial)
            dev = db.query(USBDevice).filter(USBDevice.uid == usb_uid).first()
            if not dev:
                now = datetime.now(timezone.utc)
                dev = USBDevice(uid=usb_uid, model=info.get("model"), vendor_id=vendor_id, product_id=product_id, serial=serial, size_bytes=info.get("size_bytes"), filesystem=info.get("filesystem"), volume_label=info.get("volume_label"), mount_letter=info.get("mount_letter"), status="pending", connected=True, first_seen=now, last_seen=now)
                db.add(dev); db.commit(); record_event(db, dev, "connected", "snapshot")
                found += 1
        db.close(); print(f"스냅샷 완료: {found}개 발견"); sys.exit(0)

    if args.api:
        if not FA:
            print("[!] fastapi/uvicorn/pydantic가 설치되어 있지 않습니다. `pip install fastapi uvicorn pydantic` 후 다시 실행하세요.")
            sys.exit(1)
        try:
            import uvicorn  # type: ignore
        except Exception:
            print("[!] uvicorn 미설치 — `pip install uvicorn` 필요"); sys.exit(1)

        app = create_app()
        uvicorn.run(app, host="127.0.0.1", port=args.port, reload=True)
    else:
        # 서버 없이 콘솔 모드: 위쪽에 등록된 리스트, 아래에 이벤트 로그(기존 emit_detection_log로 출력)
        if args.print_approved:
            print_approved_list()
        if IS_WINDOWS:
            print("[*] 콘솔 모드: USB 모니터 시작 (Ctrl+C 종료)…")
            t = threading.Thread(target=monitor_loop, daemon=True)
            t.start()
            try:
                while True:
                    time.sleep(0.2)
            except KeyboardInterrupt:
                stop_flag.set(); print("종료합니다…")
        else:
            print("[*] 현재 OS에서는 실시간 모니터가 비활성화됩니다 (Windows 전용). 등록된 목록만 출력합니다.")
            print_approved_list()
