import os
import re
import smtplib
import shutil
import hashlib
import threading
import platform
from pathlib import Path
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, create_engine, ForeignKey, Text
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent

# ------------- 설정값 -------------
WATCH_PATHS = [p.strip() for p in os.environ.get("COVERUP_WATCH_PATHS", r"C:\sensitiveFile").split(";") if p.strip()]       # 감시할 폴더 목록(c:\sensitiveFile파일)
QUARANTINE_DIR = Path(os.environ.get("COVERUP_QUARANTINE_DIR", "./quarantine")).resolve()
DB_URL = os.environ.get("COVERUP_DB_URL", "sqlite:///./coverup.db")
POLL_SEC = float(os.environ.get("COVERUP_POLL_SEC", "2.0"))         # 감시 폴링 간격(2초)
DEFAULT_USER = os.environ.get("ZEN_USER", None)

# 메일(선택): SMTP_* 환경변수 설정 시 승인요청 메일 전송
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")

# ------------- DB 초기화 -------------
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ------------- DB 스키마 -------------

class CoverPolicy(Base):
    __tablename__ = "cover_policies"
    id = Column(Integer, primary_key=True, autoincrement=True)
    file_type = Column(String, index=True)                 # 적용 파일 확장자 예: ".log" ".csv" ".pf"
    security_setting = Column(String)                      # 정책 강도 예: "strict" | "audit"
    register_reason = Column(String, nullable=True)        # 정책 등록 사유
    detection_event_types = Column(String)                 # 감지 이벤트 타입 CSV: "delete,move,copy,modify"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))       # 정책 생성 시각


class CoverEvent(Base):
    __tablename__ = "cover_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    path = Column(Text)                                    # 파일 경로   
    file_name = Column(String)                             # 파일 이름
    ext = Column(String, index=True)                       # 파일 확장자
    event_type = Column(String)                            # delete | move | copy | modify
    actor = Column(String)                                 # 사용자ID(대략 os.getlogin)
    hash_before = Column(String, nullable=True)
    hash_after = Column(String, nullable=True)
    blocked = Column(Boolean, default=False)
    status = Column(String, default="pending", index=True) # pending | approved | blocked
    policy_id = Column(Integer, ForeignKey("cover_policies.id"), nullable=True)
    quarantine_path = Column(Text, nullable=True)          # 격리 파일 실제 경로
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    policy = relationship("CoverPolicy")


class BlockedUser(Base):            # 차단된 사용자 목록
    __tablename__ = "blocked_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

# ------------- Pydantic 스키마 -------------

EventType = Literal["delete", "move", "copy", "modify"]

class PolicyCreate(BaseModel):
    file_type: str = Field(..., description="예: .log / .csv / .pf")
    security_setting: Literal["strict", "audit"] = "strict"
    register_reason: Optional[str] = None
    detection_event_types: List[EventType] = Field(default_factory=lambda: ["delete", "move", "copy", "modify"])

class PolicyDTO(BaseModel):
    id: int
    file_type: str
    security_setting: str
    register_reason: Optional[str]
    detection_event_types: List[str]
    created_at: datetime
    class Config: from_attributes = True

class EventDTO(BaseModel):
    id: int
    path: str
    file_name: str
    ext: str
    event_type: EventType
    actor: str
    blocked: bool
    status: str
    policy_id: Optional[int]
    quarantine_path: Optional[str]
    note: Optional[str]
    created_at: datetime
    class Config: from_attributes = True

class ApprovalAction(BaseModel):
    action: Literal["approve", "block"]
    reason: Optional[str] = None

# ------------- 유틸: 사용자/해시/로그/메일 -------------

def resolve_user() -> str:
    try:
        return DEFAULT_USER or os.getlogin()
    except Exception:
        return DEFAULT_USER or "unknown"

def sha256_of(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def emit_detection_log(signature: str, alert_text: str, dk_value: str, user: Optional[str] = None):                     
    """
    로그 포맷(컨벤션): <Sig> "<Text>" YYYY-MM-DD DK '<value>' / user '<name>'
    Sig: D/T/U/C/I/B  (여긴 C = Cover-up)
    DK : 탐지 핵심 키워드(경로/확장자/해시 등)  # 규칙 준수
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    user_name = user or resolve_user()
    line = f"{signature} \"{alert_text}\" {date_str} DK '{dk_value}' / user '{user_name}'"
    print(line)  # 콘솔에도
    # 필요 시 파일 로그 추가 가능 (USB 백엔드와 동일하게)

def send_admin_mail(subject: str, body: str):
    """SMTP 설정되어 있으면 관리자에게 메일 전송(선택)"""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and ADMIN_EMAIL):
        return
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# ------------- 정책 캐시 -------------

_policies_cache: List[CoverPolicy] = []
_cache_lock = threading.Lock()

def refresh_policy_cache():
    db = SessionLocal()
    try:
        items = db.query(CoverPolicy).all()
        with _cache_lock:
            global _policies_cache
            _policies_cache = items
    finally:
        db.close()

def match_policy(ext: str, event_type: str) -> Optional[CoverPolicy]:
    with _cache_lock:
        for p in _policies_cache:
            if p.file_type.lower() == ext.lower():
                kinds = [k.strip().lower() for k in (p.detection_event_types or "").split(",")]
                if event_type.lower() in kinds:
                    return p
    return None

# ------------- 격리/복원 -------------

def quarantine_file(src: Path) -> Optional[Path]:
    """파일을 격리 폴더로 이동(원본 잠금/보류 대용)"""
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dst = QUARANTINE_DIR / f"{src.name}.q_{stamp}"
        shutil.move(str(src), str(dst))
        return dst
    except Exception:
        return None

def restore_file(quarantine_path: Path, original_path: Path) -> bool:
    try:
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(original_path))
        return True
    except Exception:
        return False

# ------------- 감시 핸들러 -------------

def ext_of(path: str) -> str:
    return Path(path).suffix.lower()

def actor_of_event() -> str:
    return resolve_user()

def make_event(db, *, fullpath: Path, event_type: str, policy: Optional[CoverPolicy], note: Optional[str] = None,
               try_quarantine: bool = True, changed_pair: Optional[tuple]=None) -> CoverEvent:
    """
    탐지 → 이벤트 레코드 생성 + 자동 차단(격리/보류) + 승인요청 메일
    changed_pair: (before_path, after_path) for move/modify; before/after 해시 계산용
    """
    file_hash_before = None
    file_hash_after = None
    quarantine_path = None
    blocked = False
    actor = actor_of_event()

    # before/after 해시(가능할 때만)
    if changed_pair and changed_pair[0]:
        p0 = Path(changed_pair[0])
        if p0.exists():
            file_hash_before = sha256_of(p0)

    if fullpath.exists():
        file_hash_after = sha256_of(fullpath)

    # 보안 정책: strict → 일단 격리(자동 차단), audit → 기록만
    if policy and policy.security_setting.lower() == "strict":
        if try_quarantine and fullpath.exists():
            q = quarantine_file(fullpath)
            if q:
                quarantine_path = str(q)
                blocked = True

    ev = CoverEvent(
        path=str(fullpath),
        file_name=fullpath.name,
        ext=ext_of(str(fullpath)),
        event_type=event_type,
        actor=actor,
        hash_before=file_hash_before,
        hash_after=file_hash_after,
        blocked=blocked,
        status="pending",                 # 관리자가 승인/차단 결정 전
        policy_id=policy.id if policy else None,
        quarantine_path=quarantine_path,
        note=note,
    )
    db.add(ev); db.commit()

    # 탐지 로그 (시그니처 C + DK: path/ext/blocked)
    dk = f"path={ev.path} ext={ev.ext} blocked={ev.blocked}"
    emit_detection_log("C", f"Cover-up {event_type.capitalize()} Detected", dk)

    # 관리자 메일/알림
    send_admin_mail(
        subject=f"[COVER-UP] {event_type.upper()} detected: {ev.file_name}",
        body=f"Path: {ev.path}\nExt: {ev.ext}\nBlocked: {ev.blocked}\nPolicy: {policy.security_setting if policy else 'n/a'}\nEventID: {ev.id}"
    )
    return ev

class CoverupHandler(FileSystemEventHandler):
    """삭제/복사/이동/변경을 파일타입 정책에 따라 탐지"""
    def on_deleted(self, event: FileDeletedEvent):
        if event.is_directory: return
        ext = ext_of(event.src_path)
        policy = match_policy(ext, "delete")
        if not policy: return
        db = SessionLocal()
        try:
            make_event(db, fullpath=Path(event.src_path), event_type="delete", policy=policy, note="delete")
        finally:
            db.close()

    def on_created(self, event: FileCreatedEvent):
        if event.is_directory: return
        # created는 'copy'로 간주(정책이 copy를 감지하는 경우만)
        ext = ext_of(event.src_path)
        policy = match_policy(ext, "copy")
        if not policy: return
        db = SessionLocal()
        try:
            make_event(db, fullpath=Path(event.src_path), event_type="copy", policy=policy, note="created→copy")
        finally:
            db.close()

    def on_moved(self, event: FileMovedEvent):
        if event.is_directory: return
        # moved는 'move'로 처리
        dest_ext = ext_of(event.dest_path)
        policy = match_policy(dest_ext, "move")
        if not policy: return
        db = SessionLocal()
        try:
            # 이동 후 대상 파일을 격리 시도
            make_event(
                db,
                fullpath=Path(event.dest_path),
                event_type="move",
                policy=policy,
                note=f"from={event.src_path} to={event.dest_path}",
                changed_pair=(event.src_path, event.dest_path)
            )
        finally:
            db.close()

    def on_modified(self, event: FileModifiedEvent):
        if event.is_directory: return
        ext = ext_of(event.src_path)
        policy = match_policy(ext, "modify")
        if not policy: return
        db = SessionLocal()
        try:
            make_event(
                db,
                fullpath=Path(event.src_path),
                event_type="modify",
                policy=policy,
                note="content changed",
                changed_pair=(event.src_path, event.src_path)
            )
        finally:
            db.close()

# ------------- FastAPI -------------

app = FastAPI(title="Cover-up Attempt Detection Backend", version="1.0.0")

_observer: Optional[Observer] = None

@app.on_event("startup")
def on_start():
    refresh_policy_cache()
    global _observer
    handler = CoverupHandler()
    _observer = Observer()
    for p in WATCH_PATHS:
        try:
            Path(p).mkdir(parents=True, exist_ok=True)
            _observer.schedule(handler, p, recursive=True)
        except PermissionError:
            emit_detection_log("T", "Watch path not writable", f"path={p}")
            # 권한 없으면 그 경로는 건너뜀
            continue
    _observer.start()
    emit_detection_log("T", "Cover-up monitor started", f"paths={';'.join(WATCH_PATHS)}")


@app.on_event("shutdown")
def on_stop():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
    emit_detection_log("T", "Cover-up monitor stopped", "ok")

# ---- 정책 CRUD ----

@app.get("/policies", response_model=List[PolicyDTO])
def list_policies():
    db = SessionLocal()
    try:
        items = db.query(CoverPolicy).order_by(CoverPolicy.id.desc()).all()
        out = []
        for p in items:
            out.append(PolicyDTO.model_construct(
                id=p.id, file_type=p.file_type, security_setting=p.security_setting,
                register_reason=p.register_reason,
                detection_event_types=[t.strip() for t in (p.detection_event_types or "").split(",") if t.strip()],
                created_at=p.created_at
            ))
        return out
    finally:
        db.close()

@app.post("/policies", response_model=PolicyDTO)
def create_policy(req: PolicyCreate):
    db = SessionLocal()
    try:
        p = CoverPolicy(
            file_type=req.file_type if req.file_type.startswith(".") else f".{req.file_type}",
            security_setting=req.security_setting,
            register_reason=req.register_reason,
            detection_event_types=",".join(req.detection_event_types)
        )
        db.add(p); db.commit()
        refresh_policy_cache()
        return PolicyDTO.model_construct(
            id=p.id, file_type=p.file_type, security_setting=p.security_setting,
            register_reason=p.register_reason,
            detection_event_types=req.detection_event_types,
            created_at=p.created_at
        )
    finally:
        db.close()

# ---- 이벤트 조회/승인/차단 ----

@app.get("/events", response_model=List[EventDTO])
def list_events(status: Optional[str] = Query(None, description="pending|approved|blocked")):
    db = SessionLocal()
    try:
        q = db.query(CoverEvent)
        if status:
            q = q.filter(CoverEvent.status == status)
        items = q.order_by(CoverEvent.id.desc()).all()
        return [EventDTO.model_construct(**{
            "id": e.id, "path": e.path, "file_name": e.file_name, "ext": e.ext,
            "event_type": e.event_type, "actor": e.actor,
            "blocked": e.blocked, "status": e.status, "policy_id": e.policy_id,
            "quarantine_path": e.quarantine_path, "note": e.note, "created_at": e.created_at
        }) for e in items]
    finally:
        db.close()

@app.get("/events/{event_id}", response_model=EventDTO)
def get_event(event_id: int):
    db = SessionLocal()
    try:
        e = db.query(CoverEvent).get(event_id)
        if not e: raise HTTPException(404, "event not found")
        return EventDTO.model_construct(**{
            "id": e.id, "path": e.path, "file_name": e.file_name, "ext": e.ext,
            "event_type": e.event_type, "actor": e.actor,
            "blocked": e.blocked, "status": e.status, "policy_id": e.policy_id,
            "quarantine_path": e.quarantine_path, "note": e.note, "created_at": e.created_at
        })
    finally:
        db.close()

@app.post("/events/{event_id}/decision", response_model=EventDTO)
def decide_event(event_id: int, req: ApprovalAction):
    """
    approve: 격리 해제/원복, status=approved(로그만 남김)
    block  : 사용자 차단 목록에 추가, status=blocked
    """
    db = SessionLocal()
    try:
        e = db.query(CoverEvent).get(event_id)
        if not e: raise HTTPException(404, "event not found")

        if req.action == "approve":
            # 격리 파일이 있으면 원래 위치로 복원
            ok = True
            if e.quarantine_path and Path(e.quarantine_path).exists():
                ok = restore_file(Path(e.quarantine_path), Path(e.path))
            e.status = "approved"
            e.blocked = False
            e.note = (e.note or "") + f" | approved: {req.reason or ''} | restore={'ok' if ok else 'skip'}"
            db.commit()
            emit_detection_log("C", "Cover-up Approved", f"path={e.path} ext={e.ext}")
        else:
            # 사용자 차단(간단히 actor 기준)
            if e.actor:
                exists = db.query(BlockedUser).filter(BlockedUser.username == e.actor).first()
                if not exists:
                    db.add(BlockedUser(username=e.actor, reason=req.reason or f"cover-up {e.event_type}"))
            e.status = "blocked"
            e.blocked = True
            e.note = (e.note or "") + f" | blocked: {req.reason or ''}"
            db.commit()
            emit_detection_log("C", "Cover-up Blocked", f"user={e.actor} path={e.path} ext={e.ext}")

        # 관리자 메일 알림(결정 결과)
        send_admin_mail(
            subject=f"[COVER-UP:{req.action.upper()}] #{e.id} {e.file_name}",
            body=f"Status: {e.status}\nActor: {e.actor}\nPath: {e.path}\nReason: {req.reason or ''}"
        )
        return EventDTO.model_construct(**{
            "id": e.id, "path": e.path, "file_name": e.file_name, "ext": e.ext,
            "event_type": e.event_type, "actor": e.actor,
            "blocked": e.blocked, "status": e.status, "policy_id": e.policy_id,
            "quarantine_path": e.quarantine_path, "note": e.note, "created_at": e.created_at
        })
    finally:
        db.close()

# ------------- 로컬 실행 -------------
if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        print("pip install fastapi uvicorn sqlalchemy watchdog")
        raise
    uvicorn.run("coverupTrace:app", host="127.0.0.1", port=8010, reload=True)