import os
import re
import sys
import time
import threading
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, create_engine, ForeignKey, BigInteger
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# ---------------------------
# OS/WMI 준비
# ---------------------------
IS_WINDOWS = platform.system().lower().startswith("win")
if IS_WINDOWS:
    import pythoncom
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
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})        #DB(usv.db)랑 연결
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)     
Base = declarative_base()   

class USBDevice(Base):
    __tablename__ = "usb_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String, unique=True, index=True)                 # VID:PID:SERIAL (장치 고유값)
    model = Column(String, nullable=True)                       # model/vendor_id/product_id/serial 은 장치정보
    vendor_id = Column(String, index=True)                    
    product_id = Column(String, index=True)                    # vendor_id= 제조사 식별 4자리 코드(제조사) /product_id= 제품 식별 4자리 코드(제품/모델) / Ex) 0781=샌디스크 ,05AC=애플,04E8=삼성
    serial = Column(String, index=True)
    size_bytes = Column(BigInteger, nullable=True)                  # size_bytes, filesystem, volume_label, mount_letter: 용량/파일시스템/볼륨명/드라이브문자(E: 등)
    filesystem = Column(String, nullable=True)
    volume_label = Column(String, nullable=True)
    mount_letter = Column(String, nullable=True)                  
    status = Column(String, default="pending", index=True)        # 등록상태(approved | blocked | pending)
    owner = Column(String, nullable=True)
    security_level = Column(String, nullable=True)             # 보안등급
    register_reason = Column(String, nullable=True)           # 등록사유 
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))   # 최초 확인 시간
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))    # 마지막 확인 시간
    connected = Column(Boolean, default=False)                     # 현재 연결 상태

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
# Pydantic DTO / 요청 스키마        pnydantic 모델 : API 에서 쓰는 JSON 툴
# ---------------------------
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
    id: int
    uid: str
    model: Optional[str]
    vendor_id: Optional[str]
    product_id: Optional[str]
    serial: Optional[str]
    size_bytes: Optional[int]
    filesystem: Optional[str]
    volume_label: Optional[str]
    mount_letter: Optional[str]
    status: str
    owner: Optional[str]
    security_level: Optional[str]
    register_reason: Optional[str]
    first_seen: datetime
    last_seen: datetime
    connected: bool

    class Config:
        from_attributes = True

class EventDTO(BaseModel):
    id: int
    device_id: int
    event_type: str
    detail: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

# ---------------------------
# 유틸: UID/사용자/로그             
# ---------------------------
VIDPID_SERIAL_RE = re.compile(r"VID_([0-9A-F]{4}).*PID_([0-9A-F]{4}).*\\([^\\]+)$", re.IGNORECASE)  # 문자열에서 VID(제조사),PID(제품),시리얼 뽑아내는 정규식

def make_usb_uid(vendor_id: str, product_id: str, serial: str) -> str: #3개의 문자열을 받아서 합쳐서 Uid 생성
        return f"{vendor_id.upper()}:{product_id.upper()}:{serial.upper()}"

def resolve_user() -> str:  #누가 이 USB를 연결했는지 사용자명을 결정
    try:
        return DEFAULT_USER or os.getlogin()
    except Exception:
        return DEFAULT_USER or "unknown"

def emit_detection_log(signature: str, alert_text: str, dk_value: str, user: Optional[str] = None): #로그를 한줄로 기록(시그니처: [U]Usb모듈,alertText: 읽기쉬운 메시지 , DK(Detect Keyword) :핵심 식별 정보(예: uid, 드라이브 문자) )
    date_str = datetime.now().strftime("%Y-%m-%d")
    user_name = user or resolve_user()
    line = f"{signature} \"{alert_text}\" {date_str} DK '{dk_value}' / user '{user_name}'"
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    # 디버깅 편의를 위해 콘솔에도 표시
    print(line)

def record_event(db, device: USBDevice, event_type: str, detail: Optional[str] = None):     #DB에 이벤트 테이블에 한줄 추가 + 탐지로그도 같이 기록 /DB와 로그의 기록을 항상 싱크시켜야하기때문.
    ev = USBEvent(device_id=device.id, event_type=event_type, detail=detail)
    db.add(ev)
    db.commit()
    # U 시그니처로 로그 남김
    dk = f"uid={device.uid}"
    if device.mount_letter:
        dk += f" mount={device.mount_letter}"
    if device.status:
        dk += f" status={device.status}"
    emit_detection_log("U", f"USB {event_type.capitalize()}", dk)

def to_device_dto(device: USBDevice) -> DeviceDTO:      #DB객체를 API응답해서 JSON으로 변환/ 프론트가 받기 좋은 형태로 바꿔주기위해.
    """ORM -> DTO"""
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

# ---------------------------
# WMI로 USB 저장장치 스냅샷
# ---------------------------
def list_usb_storage_windows() -> List[dict]:       #꽂혀있는 USB디스크 목록을 WMI로 조회 (윈도우만됨)
    pythoncom.CoInitialize()
    try:
        conn = wmi.WMI()
        devices = []
        for disk in conn.Win32_DiskDrive(InterfaceType="USB"):
            pnp_id = disk.PNPDeviceID or ""                      # 예: 'USB\\VID_0781&PID_5583\\AA0102...'
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

def monitor_loop():         #2초마다 USB장치 스캔해서 DB/로그에 반영하는 감시 루프
    while not stop_flag.is_set():
        try:
            db = SessionLocal()
            seen_uids = set()

            # 1) 현재 연결된 USB들 스냅샷
            for info in list_usb_storage():
                vendor_id = (info.get("vendor_id") or "").upper()
                product_id = (info.get("product_id") or "").upper()
                serial = (info.get("serial") or "").upper()
                if not (vendor_id and product_id and serial):
                    continue  # 식별 핵심 값이 없으면 스킵

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
                        first_seen=now, last_seen=now
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
            if seen_uids:
                for dev in db.query(USBDevice).filter(USBDevice.connected.is_(True)).all():
                    if dev.uid not in seen_uids:
                        dev.connected = False
                        dev.last_seen = datetime.now(timezone.utc)
                        db.commit()
                        record_event(db, dev, "disconnected", None)

            db.close()
        except Exception as e:
            # 모니터링 오류는 콘솔만 (서비스 계속)
            print(f"[monitor] error: {e}")
        finally:
            stop_flag.wait(POLL_SEC)

# ---------------------------
# FastAPI
# ---------------------------
app = FastAPI(title="USB Registration Backend (Convention)", version="1.1.0")

@app.on_event("startup")
def on_start():
    # 시작 시 모니터 스레드 가동
    if IS_WINDOWS:
        t = threading.Thread(target=monitor_loop, daemon=True)
        t.start()
        emit_detection_log("T", "Service Startup", "usb_monitor=started")  # 시간(T) 시그니처 예시
    else:
        print("[*] Non-Windows: monitor disabled")

@app.on_event("shutdown")
def on_stop():
    stop_flag.set()
    emit_detection_log("T", "Service Shutdown", "usb_monitor=stopped")

# ---------------------------
# API: 장치/이벤트/등록/차단
# ---------------------------
@app.get("/devices", response_model=List[DeviceDTO])        #장치 목록(상태,연결 여부, 검색어로 필터가능)
def list_devices(
    status: Optional[str] = Query(None, description="approved|blocked|pending"),
    connected: Optional[bool] = Query(None),
    q: Optional[str] = Query(None, description="모델/시리얼/UID 부분검색"),
):
    db = SessionLocal()
    qry = db.query(USBDevice)
    if status:
        qry = qry.filter(USBDevice.status == status)
    if connected is not None:
        qry = qry.filter(USBDevice.connected.is_(connected))
    if q:
        like = f"%{q}%"
        qry = qry.filter(
            (USBDevice.model.ilike(like)) |
            (USBDevice.serial.ilike(like)) |
            (USBDevice.uid.ilike(like))
        )
    items = [to_device_dto(d) for d in qry.order_by(USBDevice.last_seen.desc()).all()]
    db.close()
    return items

@app.get("/devices/{device_id}", response_model=DeviceDTO)      #장치 한 개 상세정보
def get_device(device_id: int):
    db = SessionLocal()
    dev = db.query(USBDevice).get(device_id)
    db.close()
    if not dev:
        raise HTTPException(404, "device not found")
    return to_device_dto(dev)

@app.post("/devices/register", response_model=DeviceDTO)    #장치 승인(등록) 처리 => 상태=approved ,이벤트/로그 기록
def register_device(req: RegisterRequest):
    db = SessionLocal()
    serial = req.serial.upper()
    dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()

    # 사전 등록(연결 이력 없음)도 허용
    if not dev:
        usb_uid = make_usb_uid("UNKNOWN", "UNKNOWN", serial)
        dev = USBDevice(
            uid=usb_uid, serial=serial, status="approved",
            owner=req.owner, security_level=req.security_level,
            register_reason=req.reason, model=req.device_name
        )
        db.add(dev)
        db.commit()
        record_event(db, dev, "registered", "pre-registered")
    else:
        dev.status = "approved"
        dev.owner = req.owner or dev.owner
        dev.security_level = req.security_level or dev.security_level
        dev.register_reason = req.reason or dev.register_reason
        if req.device_name:
            dev.model = req.device_name
        db.commit()
        record_event(db, dev, "registered", "approved")

    dto = to_device_dto(dev)
    db.close()
    return dto

@app.post("/devices/block", response_model=DeviceDTO)   #장치 차단 => 상태=blocked ,이벤트/로그 기록
def block_device(req: BlockRequest):
    """장치 차단"""
    db = SessionLocal()
    serial = req.serial.upper()
    dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()
    if not dev:
        raise HTTPException(404, "device not found")
    dev.status = "blocked"
    db.commit()
    record_event(db, dev, "blocked", None)
    dto = to_device_dto(dev)
    db.close()
    return dto

@app.post("/devices/update-meta", response_model=DeviceDTO)  #장치 메타(소유자/보안등급) 갱신
def update_meta(req: UpdateMetaRequest):
    db = SessionLocal()
    serial = req.serial.upper()
    dev = db.query(USBDevice).filter(USBDevice.serial == serial).first()
    if not dev:
        raise HTTPException(404, "device not found")
    if req.owner is not None:
        dev.owner = req.owner
    if req.security_level is not None:
        dev.security_level = req.security_level
    db.commit()
    record_event(db, dev, "updated", "meta updated")
    dto = to_device_dto(dev)
    db.close()
    return dto

@app.get("/events", response_model=List[EventDTO])  #최근 이벤트 로그 목록
def list_events(limit: int = 200):
    db = SessionLocal()
    items = db.query(USBEvent).order_by(USBEvent.id.desc()).limit(limit).all()
    out = [EventDTO.model_construct(**{
        "id": e.id, "device_id": e.device_id, "event_type": e.event_type,
        "detail": e.detail, "created_at": e.created_at
    }) for e in items]
    db.close()
    return out

@app.post("/rescan")    #즉시 1회 스냅샷 스캔(백그라운드 루프는 유지)
def rescan_now():
    if not IS_WINDOWS:
        emit_detection_log("T", "Rescan Skipped", "platform=non-windows")
        return {"ok": True, "found": 0}

    db = SessionLocal()
    found = 0
    for info in list_usb_storage():
        vendor_id = (info.get("vendor_id") or "").upper()
        product_id = (info.get("product_id") or "").upper()
        serial = (info.get("serial") or "").upper()
        if not (vendor_id and product_id and serial):
            continue
        usb_uid = make_usb_uid(vendor_id, product_id, serial)
        dev = db.query(USBDevice).filter(USBDevice.uid == usb_uid).first()
        now = datetime.now(timezone.utc)

        if not dev:
            dev = USBDevice(
                uid=usb_uid, model=info.get("model"),
                vendor_id=vendor_id, product_id=product_id, serial=serial,
                size_bytes=info.get("size_bytes"),
                filesystem=info.get("filesystem"),
                volume_label=info.get("volume_label"),
                mount_letter=info.get("mount_letter"),
                status="pending", connected=True,
                first_seen=now, last_seen=now
            )
            db.add(dev)
            db.commit()
            record_event(db, dev, "connected", "rescan")
            found += 1
        else:
            dev.connected = True
            dev.last_seen = now
            db.commit()

    db.close()
    emit_detection_log("T", "Rescan Finished", f"found={found}")
    return {"ok": True, "found": found}

# ---------------------------
# 로컬 실행
# ---------------------------
if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        print("pip install fastapi uvicorn sqlalchemy wmi pywin32")
        sys.exit(1)
    uvicorn.run("usb_backend_convention:app", host="127.0.0.1", port=8000, reload=True)