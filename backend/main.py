
import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr, Field

from indicators import analyze
from market_data import get_candles

# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "admin.db"))

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

SECRET_KEY = os.getenv("SECRET_KEY", "")

if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters")

if not ADMIN_EMAIL or not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_EMAIL and ADMIN_PASSWORD are required")

app = FastAPI(
    title="Market Analysis Dashboard",
    version="2.0.0"
)

ONLINE_SECONDS = 300
SESSION_DAYS = 7


# =========================
# DATABASE
# =========================

def connect():
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:

        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            last_seen TEXT
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT,
            details TEXT,
            created_at TEXT
        )
        """)

        db.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_user
        ON sessions(user_id)
        """)

        existing = db.execute(
            "SELECT id FROM users WHERE email=?",
            (ADMIN_EMAIL,)
        ).fetchone()

        if not existing:
            password_hash = bcrypt.hashpw(
                ADMIN_PASSWORD.encode(),
                bcrypt.gensalt()
            ).decode()

            db.execute("""
            INSERT INTO users
            (email, password_hash, role, status, created_at)
            VALUES (?, ?, 'super_admin', 'approved', ?)
            """, (
                ADMIN_EMAIL,
                password_hash,
                datetime.now(timezone.utc).isoformat()
            ))


init_db()


# =========================
# HELPERS
# =========================

def now():
    return datetime.now(timezone.utc)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def audit(db, actor, action, details=""):
    db.execute("""
    INSERT INTO audit_logs
    (actor, action, details, created_at)
    VALUES (?, ?, ?, ?)
    """, (
        actor,
        action,
        details,
        now().isoformat()
    ))


def public_user(row):
    return {
        "id": row["id"],
        "email": row["email"],
        "role": row["role"],
        "status": row["status"],
        "created_at": row["created_at"],
        "last_seen": row["last_seen"]
    }


# =========================
# AUTHENTICATION
# =========================

def current_user(authorization: str = Header(None)):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")

    token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(401, "Invalid session")

    token_hash = hash_token(token)

    with connect() as db:

        session = db.execute("""
        SELECT s.user_id, s.expires_at,
               u.id, u.email, u.role, u.status
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """, (token_hash,)).fetchone()

        if not session:
            raise HTTPException(401, "Invalid session")

        if datetime.fromisoformat(session["expires_at"]) < now():
            db.execute(
                "DELETE FROM sessions WHERE token_hash=?",
                (token_hash,)
            )
            raise HTTPException(401, "Session expired")

        if session["status"] != "approved":
            raise HTTPException(403, "Account not approved")

        db.execute(
            "UPDATE users SET last_seen=? WHERE id=?",
            (now().isoformat(), session["id"])
        )

        return {
            "id": session["id"],
            "email": session["email"],
            "role": session["role"]
        }


def admin_only(user=Depends(current_user)):
    if user["role"] not in ("super_admin", "sub_admin"):
        raise HTTPException(403, "Admin access required")
    return user


def super_admin_only(user=Depends(current_user)):
    if user["role"] != "super_admin":
        raise HTTPException(403, "Super admin access required")
    return user


# =========================
# REQUEST MODELS
# =========================

class RegisterData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class LoginData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class PasswordChangeData(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=12, max_length=72)


class SubAdminData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)


# =========================
# REGISTER
# =========================

@app.post("/register")
def register(data: RegisterData):

    email = str(data.email).lower().strip()

    password_hash = bcrypt.hashpw(
        data.password.encode(),
        bcrypt.gensalt()
    ).decode()

    try:
        with connect() as db:
            db.execute("""
            INSERT INTO users
            (email, password_hash, role, status, created_at)
            VALUES (?, ?, 'user', 'pending', ?)
            """, (
                email,
                password_hash,
                now().isoformat()
            ))

        return {
            "message": "Registration successful. Awaiting approval."
        }

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(data: LoginData):

    email = str(data.email).lower().strip()

    with connect() as db:

        user = db.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if not user or not bcrypt.checkpw(
            data.password.encode(),
            user["password_hash"].encode()
        ):
            raise HTTPException(401, "Invalid email or password")

        if user["status"] != "approved":
            raise HTTPException(403, "Account is pending or blocked")

        token = secrets.token_urlsafe(48)

        expires = now() + timedelta(days=SESSION_DAYS)

        db.execute("""
        INSERT INTO sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
        """, (
            hash_token(token),
            user["id"],
            expires.isoformat()
        ))

        db.execute(
            "UPDATE users SET last_seen=? WHERE id=?",
            (now().isoformat(), user["id"])
        )

        audit(db, email, "LOGIN")

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }


# =========================
# LOGOUT
# =========================

@app.post("/logout")
def logout(user=Depends(current_user),
           authorization: str = Header(None)):

    token = authorization.split(" ", 1)[1].strip()

    with connect() as db:
        db.execute(
            "DELETE FROM sessions WHERE token_hash=?",
            (hash_token(token),)
        )
        audit(db, user["email"], "LOGOUT")

    return {"message": "Logged out"}


# =========================
# PROFILE
# =========================

@app.get("/admin/api/me")
def my_profile(user=Depends(current_user)):
    return user


# =========================
# CHANGE PASSWORD
# =========================

@app.post("/admin/api/change-password")
def change_password(
    data: PasswordChangeData,
    user=Depends(current_user)
):

    with connect() as db:

        account = db.execute(
            "SELECT password_hash FROM users WHERE id=?",
            (user["id"],)
        ).fetchone()

        if not bcrypt.checkpw(
            data.current_password.encode(),
            account["password_hash"].encode()
        ):
            raise HTTPException(400, "Current password incorrect")

        if data.current_password == data.new_password:
            raise HTTPException(400, "Choose a different password")

        new_hash = bcrypt.hashpw(
            data.new_password.encode(),
            bcrypt.gensalt()
        ).decode()

        db.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (new_hash, user["id"])
        )

        db.execute(
            "DELETE FROM sessions WHERE user_id=?",
            (user["id"],)
        )

        audit(db, user["email"], "PASSWORD_CHANGED")

    return {
        "message": "Password changed. Please login again."
    }


# =========================
# ADMIN STATISTICS
# =========================

@app.get("/admin/api/stats")
def admin_stats(admin=Depends(admin_only)):

    cutoff = (now() - timedelta(seconds=ONLINE_SECONDS)).isoformat()

    with connect() as db:

        total = db.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        pending = db.execute(
            "SELECT COUNT(*) FROM users WHERE status='pending'"
        ).fetchone()[0]

        approved = db.execute(
            "SELECT COUNT(*) FROM users WHERE status='approved'"
        ).fetchone()[0]

        blocked = db.execute(
            "SELECT COUNT(*) FROM users WHERE status='blocked'"
        ).fetchone()[0]

        online = db.execute(
            "SELECT COUNT(*) FROM users WHERE last_seen>=?",
            (cutoff,)
        ).fetchone()[0]

    return {
        "total_users": total,
        "pending_users": pending,
        "approved_users": approved,
        "blocked_users": blocked,
        "online_users": online
    }


# =========================
# USER MANAGEMENT
# =========================

@app.get("/admin/api/users")
def list_users(admin=Depends(admin_only)):

    with connect() as db:

        rows = db.execute("""
        SELECT id, email, role, status, created_at, last_seen
        FROM users
        ORDER BY id DESC
        """).fetchall()

    return [public_user(row) for row in rows]


@app.post("/admin/api/users/{user_id}/approve")
def approve_user(user_id: int, admin=Depends(admin_only)):

    with connect() as db:

        result = db.execute("""
        UPDATE users SET status='approved'
        WHERE id=? AND role='user'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

        audit(db, admin["email"], "USER_APPROVED", str(user_id))

    return {"message": "User approved"}


@app.post("/admin/api/users/{user_id}/block")
def block_user(user_id: int, admin=Depends(admin_only)):

    with connect() as db:

        result = db.execute("""
        UPDATE users SET status='blocked'
        WHERE id=? AND role='user'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

        db.execute("""
        DELETE FROM sessions
        WHERE user_id=?
        """, (user_id,))

        audit(db, admin["email"], "USER_BLOCKED", str(user_id))

    return {"message": "User blocked"}


@app.post("/admin/api/users/{user_id}/unblock")
def unblock_user(user_id: int, admin=Depends(admin_only)):

    with connect() as db:

        result = db.execute("""
        UPDATE users SET status='approved'
        WHERE id=? AND role='user' AND status='blocked'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "Blocked user not found")

        audit(db, admin["email"], "USER_UNBLOCKED", str(user_id))

    return {"message": "User unblocked"}


# =========================
# SUB ADMIN MANAGEMENT
# =========================

@app.post("/admin/api/subadmins")
def create_subadmin(
    data: SubAdminData,
    admin=Depends(super_admin_only)
):

    email = str(data.email).lower().strip()

    password_hash = bcrypt.hashpw(
        data.password.encode(),
        bcrypt.gensalt()
    ).decode()

    try:
        with connect() as db:

            db.execute("""
            INSERT INTO users
            (email, password_hash, role, status, created_at)
            VALUES (?, ?, 'sub_admin', 'approved', ?)
            """, (
                email,
                password_hash,
                now().isoformat()
            ))

            audit(db, admin["email"], "SUBADMIN_CREATED", email)

        return {"message": "Sub admin created"}

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already exists")


@app.get("/admin/api/subadmins")
def list_subadmins(admin=Depends(super_admin_only)):

    with connect() as db:

        rows = db.execute("""
        SELECT id, email, role, status, created_at, last_seen
        FROM users WHERE role='sub_admin'
        ORDER BY id DESC
        """).fetchall()

    return [public_user(row) for row in rows]


@app.post("/admin/api/subadmins/{user_id}/disable")
def disable_subadmin(
    user_id: int,
    admin=Depends(super_admin_only)
):

    with connect() as db:

        result = db.execute("""
        UPDATE users SET status='blocked'
        WHERE id=? AND role='sub_admin'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "Sub admin not found")

        db.execute(
            "DELETE FROM sessions WHERE user_id=?",
            (user_id,)
        )

        audit(db, admin["email"], "SUBADMIN_DISABLED", str(user_id))

    return {"message": "Sub admin disabled"}


# =========================
# ONLINE USERS
# =========================

@app.get("/admin/api/online-users")
def online_users(admin=Depends(admin_only)):

    cutoff = (now() - timedelta(seconds=ONLINE_SECONDS)).isoformat()

    with connect() as db:

        rows = db.execute("""
        SELECT id, email, role, status, created_at, last_seen
        FROM users
        WHERE last_seen>=? AND status='approved'
        ORDER BY last_seen DESC
        """, (cutoff,)).fetchall()

    return [public_user(row) for row in rows]


# =========================
# AUDIT LOGS
# =========================

@app.get("/admin/api/logs")
def get_logs(admin=Depends(admin_only)):

    with connect() as db:

        rows = db.execute("""
        SELECT id, actor, action, details, created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 200
        """).fetchall()

    return [dict(row) for row in rows]


# =========================
# MARKET ANALYSIS
# =========================

@app.get("/admin/api/market-analysis")
def market_analysis(
    symbol: str = "BTCUSDT",
    interval: str = "1m",
    user=Depends(current_user)
):

    allowed_intervals = {
        "1m", "2m", "3m", "5m",
        "15m", "30m", "1h", "4h", "1d"
    }

    symbol = symbol.upper().strip()

    if interval not in allowed_intervals:
        raise HTTPException(400, "Unsupported interval")

    if not symbol.isalnum() or len(symbol) > 20:
        raise HTTPException(400, "Invalid symbol")

    try:
        candles = get_candles(symbol, interval)

        if not candles:
            raise HTTPException(503, "Market data unavailable")

        closes = [float(c["close"]) for c in candles]

        indicators = analyze(closes)

        return {
            "symbol": symbol,
            "interval": interval,
            "market": "crypto",
            "provider": "Binance Spot",
            "candles": candles,
            "indicators": indicators,
            "notice": (
                "Educational historical analysis only. "
                "Not a trading recommendation."
            )
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            503,
            "Market data provider temporarily unavailable"
        )


# =========================
# MARKET PROVIDER STATUS
# =========================

@app.get("/admin/api/market-status")
def market_status(user=Depends(current_user)):

    return {
        "crypto": {
            "available": True,
            "provider": "Binance Spot"
        },
        "forex": {
            "available": False,
            "provider": None,
            "message": "Provider not connected"
        },
        "stocks": {
            "available": False,
            "provider": None,
            "message": "Provider not connected"
        },
        "otc": {
            "available": False,
            "provider": None,
            "message": "Verified OTC provider not connected"
        }
    }


# =========================
# HEALTH CHECK
# =========================

@app.get("/health")
def health():
    return {
        "status": "online",
        "application": "Market Analysis Dashboard"
    }


@app.get("/")
def root():
    return {
        "status": "online",
        "application": "Market Analysis Dashboard",
        "dashboard": "/dashboard",
        "admin_dashboard": "/admin/dashboard",
        "api_docs": "/docs"
    }


# =========================
# DASHBOARD PAGES
# =========================

@app.get("/dashboard")
def user_dashboard():

    file = BASE_DIR / "dashboard.html"

    if not file.exists():
        raise HTTPException(404, "dashboard.html not found")

    return FileResponse(str(file))


@app.get("/admin/dashboard")
def admin_dashboard():

    file = BASE_DIR / "dashboard.html"

    if not file.exists():
        raise HTTPException(404, "dashboard.html not found")

    return FileResponse(str(file))
