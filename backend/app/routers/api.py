from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Header
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models import User, Device, Resource, AccessRequest, RiskAssessment, SecurityEvent, AccessPolicy, UserSession
from ..security.auth import current_user, require_admin, hash_password, verify_password, create_token
from ..security.auth import SECRET, ALGORITHM
from jose import jwt, JWTError
from ..risk_engine import evaluate

router = APIRouter(prefix="/api")
def event(db, kind, message, user_id=None, severity="info", metadata=None):
    db.add(SecurityEvent(user_id=user_id, event_type=kind, message=message, severity=severity, metadata_json=metadata or {}))

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
class LoginIn(BaseModel):
    email: EmailStr
    password: str
class RequestIn(BaseModel):
    resource_id: int
    device_id: int | None = None
    location: str = "normal"
    time_context: str | None = None
    failed_attempts: int = Field(default=0, ge=0, le=10)
class SimulateIn(RequestIn):
    user_id: int
    device_state: str = "trusted"
class DeviceStateIn(BaseModel): state: str
class ResourceIn(BaseModel):
    name: str
    description: str = ""
    sensitivity: str = "medium"
class PolicyIn(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    max_allow_score: int = Field(ge=0, le=100)
    max_restrict_score: int = Field(ge=0, le=100)

@router.post("/auth/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(func.lower(User.email) == data.email.lower()).first(): raise HTTPException(409, "Email is already registered")
    user = User(name=data.name, email=data.email.lower(), password_hash=hash_password(data.password)); db.add(user); db.flush()
    event(db, "registration", "Account registered", user.id); db.commit(); db.refresh(user)
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}

@router.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(func.lower(User.email) == data.email.lower()).first()
    if not user or not verify_password(data.password, user.password_hash):
        if user: user.failed_logins += 1
        event(db, "login_failure", "Login failed", user.id if user else None, "warning"); db.commit()
        raise HTTPException(401, "Invalid email or password")
    user.failed_logins = 0; token = create_token(user, db); event(db, "login_success", "Login successful", user.id); db.commit()
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}}

@router.post("/auth/logout")
def logout(user=Depends(current_user), authorization: str | None = Header(default=None), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(authorization.split(" ", 1)[1], SECRET, algorithms=[ALGORITHM])
        session = db.query(UserSession).filter_by(token_jti=payload["jti"]).first()
        if session: session.revoked = True
        event(db, "logout", "User logged out", user.id); db.commit()
    except (AttributeError, IndexError, JWTError, KeyError):
        raise HTTPException(401, "Invalid session")
    return {"message": "Logged out"}

@router.get("/auth/me")
def me(user=Depends(current_user)): return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "status": user.status}

@router.get("/users")
def users(admin=Depends(require_admin), db: Session = Depends(get_db)):
    return [{"id": x.id, "name": x.name, "email": x.email, "role": x.role, "status": x.status, "failed_logins": x.failed_logins, "created_at": x.created_at} for x in db.query(User).order_by(User.id).all()]

@router.get("/sessions")
def sessions(admin=Depends(require_admin), db: Session = Depends(get_db)):
    return [{"id": s.id, "user_id": s.user_id, "user": db.get(User, s.user_id).email, "created_at": s.created_at, "expires_at": s.expires_at, "revoked": s.revoked} for s in db.query(UserSession).order_by(UserSession.created_at.desc()).limit(500).all()]

@router.get("/devices")
def devices(user=Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Device)
    if user.role != "admin": q = q.filter(Device.user_id == user.id)
    return [{"id": d.id, "user_id": d.user_id, "user": d.user.name, "name": d.name, "state": d.state, "last_seen": d.last_seen} for d in q.all()]

class DeviceIn(BaseModel): name: str = Field(min_length=2, max_length=120)

@router.post("/devices", status_code=201)
def register_device(data: DeviceIn, user=Depends(current_user), db: Session = Depends(get_db)):
    fingerprint = str(uuid4())
    d = Device(user_id=user.id, name=data.name, fingerprint=fingerprint, state="unknown")
    db.add(d); db.flush(); event(db, "new_device", f"New device registered: {d.name}", user.id, "warning", {"device_id": d.id}); db.commit()
    return {"id": d.id, "name": d.name, "state": d.state}

@router.patch("/devices/{device_id}")
def set_device(device_id: int, data: DeviceStateIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    if data.state not in {"trusted", "unknown", "warning", "compromised"}: raise HTTPException(422, "Invalid device state")
    d = db.get(Device, device_id)
    if not d: raise HTTPException(404, "Device not found")
    d.state = data.state; event(db, "device_state_changed", f"Device {d.name} state changed to {d.state}", admin.id, "warning" if d.state == "compromised" else "info"); db.commit()
    return {"id": d.id, "state": d.state}

@router.get("/resources")
def resources(user=Depends(current_user), db: Session = Depends(get_db)):
    return [{"id": r.id, "name": r.name, "description": r.description, **({"sensitivity": r.sensitivity} if user.role == "admin" else {})} for r in db.query(Resource).filter_by(active=True).all()]

@router.post("/resources", status_code=201)
def add_resource(data: ResourceIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    if data.sensitivity not in {"low", "medium", "high", "critical"}: raise HTTPException(422, "Invalid sensitivity")
    r = Resource(**data.model_dump()); db.add(r); db.commit(); db.refresh(r); return {"id": r.id, **data.model_dump()}

def make_decision(user, resource, device_state, location, time_context, failed, db, device_id=None, simulated=False):
    result = evaluate(user_status=user.status, device_state=device_state, location=location, time_context=time_context, failed_attempts=failed + user.failed_logins, sensitivity=resource.sensitivity)
    policy = db.query(AccessPolicy).filter_by(enabled=True).order_by(AccessPolicy.id).first()
    allow_limit = policy.max_allow_score if policy else 29
    restrict_limit = policy.max_restrict_score if policy else 69
    if device_state == "compromised" or user.status != "active" or result["score"] > restrict_limit:
        result["decision"] = "DENY"
    elif result["score"] > allow_limit:
        result["decision"] = "RESTRICT"
    else:
        result["decision"] = "ALLOW"
    req = AccessRequest(user_id=user.id, resource_id=resource.id, device_id=device_id, location=location, time_context=time_context, failed_attempts=failed, decision=result["decision"])
    db.add(req); db.flush()
    db.add(RiskAssessment(access_request_id=req.id, score=result["score"], level=result["level"], factors=result["factors"], reasons=result["reasons"]))
    event(db, "access_requested", f"Access requested for {resource.name}", user.id, metadata={"request_id": req.id, "simulated": simulated})
    event(db, "access_" + result["decision"].lower(), f"Access {result['decision'].lower()} for {resource.name}", user.id, "critical" if result["decision"] == "DENY" else "warning" if result["decision"] == "RESTRICT" else "info", {"request_id": req.id, "score": result["score"]})
    if result["decision"] == "DENY": event(db, "policy_violation", f"Policy blocked access to {resource.name}", user.id, "critical", {"request_id": req.id})
    if result["score"] >= 70: event(db, "high_risk_detection", "High-risk access context detected", user.id, "critical", {"request_id": req.id, "score": result["score"]})
    db.commit()
    return {"request_id": req.id, **result}

@router.post("/access-requests", status_code=201)
def request_access(data: RequestIn, user=Depends(current_user), db: Session = Depends(get_db)):
    resource = db.get(Resource, data.resource_id)
    if not resource or not resource.active: raise HTTPException(404, "Resource not found")
    device_state = "unknown"
    if data.device_id:
        device = db.get(Device, data.device_id)
        if not device or (user.role != "admin" and device.user_id != user.id): raise HTTPException(404, "Device not found")
        device_state = device.state; device.last_seen = datetime.now(timezone.utc)
    if data.location not in {"normal", "new", "suspicious"} or data.time_context not in {None, "normal", "unusual"}: raise HTTPException(422, "Invalid context")
    request_time = data.time_context or ("normal" if 7 <= datetime.now(timezone.utc).hour < 19 else "unusual")
    result = make_decision(user, resource, device_state, data.location, request_time, data.failed_attempts, db, data.device_id)
    if user.role != "admin": return {"request_id": result["request_id"], "decision": result["decision"], "message": "Access permitted" if result["decision"] == "ALLOW" else "Step-up verification required" if result["decision"] == "RESTRICT" else "Access denied by security policy"}
    return result

@router.post("/risk/evaluate")
def simulate(data: SimulateIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, data.user_id); resource = db.get(Resource, data.resource_id)
    if not user or not resource: raise HTTPException(404, "User or resource not found")
    if data.device_state not in {"trusted", "unknown", "warning", "compromised"} or data.location not in {"normal", "new", "suspicious"} or data.time_context not in {"normal", "unusual"}: raise HTTPException(422, "Invalid scenario context")
    return make_decision(user, resource, data.device_state, data.location, data.time_context, data.failed_attempts, db, data.device_id, True)

@router.get("/access-requests")
def requests(user=Depends(current_user), db: Session = Depends(get_db), decision: str | None = None):
    q = db.query(AccessRequest).order_by(AccessRequest.created_at.desc())
    if user.role != "admin": q = q.filter(AccessRequest.user_id == user.id)
    if decision: q = q.filter(AccessRequest.decision == decision.upper())
    result = []
    for a in q.limit(500).all():
        item = {"id": a.id, "user_id": a.user_id, "user": a.user.name, "resource": a.resource.name, "sensitivity": a.resource.sensitivity, "device_id": a.device_id, "decision": a.decision, "created_at": a.created_at}
        if user.role == "admin" and a.risk_assessment:
            item["risk"] = {"score": a.risk_assessment.score, "level": a.risk_assessment.level, "factors": a.risk_assessment.factors, "reasons": a.risk_assessment.reasons}
        result.append(item)
    return result

@router.get("/security-events")
def events(user=Depends(current_user), db: Session = Depends(get_db), limit: int = Query(default=200, le=500)):
    q = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc())
    if user.role != "admin": q = q.filter(SecurityEvent.user_id == user.id)
    return [{"id": e.id, "user_id": e.user_id, "event_type": e.event_type, "severity": e.severity, "message": e.message, "metadata": e.metadata_json if user.role == "admin" else {}, "created_at": e.created_at} for e in q.limit(limit).all()]

@router.get("/policies")
def policies(user=Depends(current_user), db: Session = Depends(get_db)):
    if user.role != "admin": raise HTTPException(403, "Administrator role required")
    return [{"id": p.id, "name": p.name, "description": p.description, "enabled": p.enabled, "max_allow_score": p.max_allow_score, "max_restrict_score": p.max_restrict_score} for p in db.query(AccessPolicy).all()]

@router.post("/policies", status_code=201)
def add_policy(data: PolicyIn, admin=Depends(require_admin), db: Session = Depends(get_db)):
    p = AccessPolicy(**data.model_dump()); db.add(p); db.commit(); db.refresh(p); return {"id": p.id, **data.model_dump()}

@router.get("/dashboard/stats")
def stats(user=Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(AccessRequest)
    if user.role != "admin": q = q.filter(AccessRequest.user_id == user.id)
    allreq = q.all()
    result = {"users": db.query(User).count() if user.role == "admin" else 1, "devices": db.query(Device).filter(Device.user_id == user.id).count() if user.role != "admin" else db.query(Device).count(), "requests": len(allreq), "allowed": sum(a.decision == "ALLOW" for a in allreq), "restricted": sum(a.decision == "RESTRICT" for a in allreq), "denied": sum(a.decision == "DENY" for a in allreq)}
    if user.role == "admin":
        result["high_risk"] = sum(bool(a.risk_assessment and a.risk_assessment.score >= 70) for a in allreq)
        result["risk_distribution"] = {level: sum(a.risk_assessment.level == level for a in allreq if a.risk_assessment) for level in ("low", "medium", "high")}
    return result
