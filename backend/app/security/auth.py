import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import jwt, JWTError
from pwdlib import PasswordHash
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, UserSession

password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)
SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
ALGORITHM = "HS256"
def hash_password(password: str) -> str: return password_hash.hash(password)
def verify_password(password: str, hashed: str) -> bool: return password_hash.verify(password, hashed)

def create_token(user: User, db: Session) -> str:
    now = datetime.now(timezone.utc); expires = now + timedelta(minutes=int(os.getenv("JWT_EXPIRE_MINUTES", "60"))); jti = str(uuid4())
    token = jwt.encode({"sub": str(user.id), "role": user.role, "jti": jti, "iat": now, "exp": expires}, SECRET, algorithm=ALGORITHM)
    db.add(UserSession(user_id=user.id, token_jti=jti, expires_at=expires)); db.commit()
    return token

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    try:
        if credentials is None: raise ValueError("Missing bearer token")
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=[ALGORITHM]); uid = int(payload["sub"]); jti = payload["jti"]
    except (JWTError, KeyError, ValueError): raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    session = db.query(UserSession).filter_by(token_jti=jti, revoked=False).first()
    user = db.get(User, uid)
    if not session or not user or user.status != "active": raise HTTPException(status_code=401, detail="Session is not active")
    return user

def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin": raise HTTPException(status_code=403, detail="Administrator role required")
    return user
