"""Hardened FastAPI application — production-quality security controls."""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from openai import OpenAI
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import Column, DateTime, Integer, String, create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ─── Database setup (connection pooling via SQLAlchemy engine) ──────

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class UsageRecord(Base):
    __tablename__ = "usage_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False)
    tokens = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    event_id = Column(String, primary_key=True)
    type = Column(String, nullable=False)
    processed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ─── Dependency: database session ──────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Auth via JWT ──────────────────────────────────────────────────

SECRET_KEY = os.environ.get("JWT_SECRET", "change-me-in-production")
ALGORITHM = "HS256"


class TokenPayload(BaseModel):
    sub: str
    role: str = "user"
    exp: datetime


class AuthenticatedUser(BaseModel):
    id: str
    role: str


async def get_current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> AuthenticatedUser:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authentication token")

    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub", "")
        role: str = payload.get("role", "user")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    return AuthenticatedUser(id=user_id, role=role)


async def require_admin(current_user: Annotated[AuthenticatedUser, Depends(get_current_user)]) -> AuthenticatedUser:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


# ─── Input validation via Pydantic ─────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)

    @field_validator("message")
    @classmethod
    def sanitize_message(cls, v: str) -> str:
        return v.strip()


class DeleteUserRequest(BaseModel):
    user_id: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    text: str


# ─── Rate limiting ─────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=["100/15minutes"])


# ─── Structured logger ────────────────────────────────────────────

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


# ─── OpenAI client (module-level for connection reuse) ─────────────

openai_client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY", ""),
    timeout=30.0,
    max_retries=2,
)


# ─── App lifespan ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info({"event": "app.startup", "timestamp": datetime.now(timezone.utc).isoformat()})
    yield
    engine.dispose()
    logger.info({"event": "app.shutdown", "timestamp": datetime.now(timezone.utc).isoformat()})


# ─── App creation ──────────────────────────────────────────────────

app = FastAPI(title="Hardened API", lifespan=lifespan)

# CORS: restricted origins, not wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Rate limit error handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


# ─── Health check ──────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ─── AI Chat endpoint ──────────────────────────────────────────────

MONTHLY_QUOTA = 1000


@app.post("/api/chat", response_model=ChatResponse)
@limiter.limit("10/minute")
async def chat(
    request: Request,
    body: ChatRequest,
    current_user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    # Quota check (parameterized via ORM)
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    usage_count = db.query(UsageRecord).filter(
        UsageRecord.user_id == current_user.id,
        UsageRecord.created_at >= cutoff,
    ).count()

    if usage_count >= MONTHLY_QUOTA:
        logger.warning({"event": "quota.exceeded", "user_id": current_user.id})
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Monthly quota exceeded")

    try:
        completion = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": body.message}],
            max_tokens=2048,
        )

        # Record usage (parameterized via ORM)
        db.add(UsageRecord(user_id=current_user.id, type="chat", tokens=completion.usage.total_tokens or 0))
        db.commit()

        logger.info({"event": "chat.completed", "user_id": current_user.id, "tokens": completion.usage.total_tokens})
        return ChatResponse(text=completion.choices[0].message.content or "")
    except Exception as exc:
        logger.error({"event": "chat.error", "user_id": current_user.id, "error": str(exc)})
        raise HTTPException(status_code=500, detail="Internal server error")


# ─── Admin: delete user ────────────────────────────────────────────

@app.delete("/api/admin/users")
async def delete_user(
    request: Request,
    body: DeleteUserRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    # Audit log
    logger.info({"event": "admin.delete_user", "admin_id": admin.id, "target_user_id": body.user_id})

    user = db.query(User).filter(User.id == body.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"ok": True}


# ─── Stripe webhook ────────────────────────────────────────────────

import stripe  # noqa: E402

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request, db: Annotated[Session, Depends(get_db)]):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        logger.warning({"event": "webhook.missing_signature"})
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    try:
        event_obj = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as exc:
        logger.error({"event": "webhook.signature_failed", "error": str(exc)})
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Idempotency check via ORM (parameterized)
    existing = db.query(WebhookEvent).filter(WebhookEvent.event_id == event_obj["id"]).first()
    if existing:
        logger.info({"event": "webhook.duplicate", "event_id": event_obj["id"]})
        return {"received": True, "duplicate": True}

    if event_obj["type"] == "checkout.session.completed":
        db.add(WebhookEvent(event_id=event_obj["id"], type=event_obj["type"]))
        db.commit()
        logger.info({"event": "webhook.processed", "event_id": event_obj["id"]})

    return {"received": True}
