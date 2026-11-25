import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import Base, engine, SessionLocal
from .models import User, Resource, AccessPolicy
from .security.auth import hash_password
from .routers.api import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Resource).count() == 0:
            db.add_all([
                Resource(name="Employee Portal", description="General company information", sensitivity="low"),
                Resource(name="Engineering Repository", description="Internal source code and project records", sensitivity="medium"),
                Resource(name="Customer Records", description="Sensitive customer information", sensitivity="high"),
                Resource(name="Finance Vault", description="Critical financial and credential records", sensitivity="critical"),
            ])
        if db.query(AccessPolicy).count() == 0:
            db.add(AccessPolicy(name="Default adaptive access", description="Allow below 30, restrict from 30, deny at 70 or on compromised devices", max_allow_score=29, max_restrict_score=69))
        email, password = os.getenv("BOOTSTRAP_ADMIN_EMAIL"), os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
        if email and password and not db.query(User).filter_by(email=email.lower()).first():
            db.add(User(name="Security Administrator", email=email.lower(), password_hash=hash_password(password), role="admin"))
        db.commit()
    finally: db.close()
    yield

app = FastAPI(title="Risk-Adaptive Zero-Trust Access Control", version="1.0.0", description="Context-aware access decisions with auditable risk assessments.", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:5173").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)

@app.get("/health", tags=["health"])
def health(): return {"status": "ok"}
