
import os
import sqlite3
import bcrypt
import hmac
import hashlib
import base64
import time

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Bookmarklet Analysis Bot")
security = HTTPBearer()

DB = "bot.db"
SECRET = os.getenv("SECRET_KEY", "")

def connect():
    return sqlite3.connect(DB)

@app.on_event("startup")
def setup():
    with connect() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            status TEXT DEFAULT 'pending'
        )
        """)

        email = os.getenv("ADMIN_EMAIL")
        password = os.getenv("ADMIN_PASSWORD")

        if email and password:
            exists = db.execute(
                "SELECT id FROM users WHERE email=?",
                (email.lower(),)
            ).fetchone()

            if not exists:
                hashed = bcrypt.hashpw(
                    password.encode(),
                    bcrypt.gensalt()
                ).decode()

                db.execute(
                    """INSERT INTO users
                    (email,password,role,status)
                    VALUES (?,?,?,?)""",
                    (email.lower(), hashed,
                     "super_admin", "approved")
                )

class RegisterData(BaseModel):
    email: EmailStr
    password: str

class LoginData(BaseModel):
    email: EmailStr
    password: str

def make_token(user_id):
    if not SECRET:
        raise HTTPException(500, "Server secret not configured")

    expiry = int(time.time()) + 86400
    payload = f"{user_id}:{expiry}"
    signature = hmac.new(
        SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return base64.urlsafe_b64encode(
        f"{payload}:{signature}".encode()
    ).decode()

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        decoded = base64.urlsafe_b64decode(
            credentials.credentials.encode()
        ).decode()

        user_id, expiry, signature = decoded.split(":")
        payload = f"{user_id}:{expiry}"

        expected = hmac.new(
            SECRET.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if not SECRET or not hmac.compare_digest(
            signature, expected
        ) or int(expiry) < int(time.time()):
            raise ValueError()

        with connect() as db:
            row = db.execute(
                """SELECT id,email,role,status
                FROM users WHERE id=?""",
                (int(user_id),)
            ).fetchone()

        if not row or row[3] != "approved":
            raise ValueError()

        return {
            "id": row[0],
            "email": row[1],
            "role": row[2]
        }

    except Exception:
        raise HTTPException(401, "Invalid or expired login")

def admin_only(user=Depends(current_user)):
    if user["role"] not in ("super_admin", "sub_admin"):
        raise HTTPException(403, "Admin access required")
    return user

@app.get("/")
def home():
    return {"status": "online"}

@app.post("/register")
def register(data: RegisterData):
    if len(data.password) < 12:
        raise HTTPException(
            400, "Password must be at least 12 characters"
        )

    hashed = bcrypt.hashpw(
        data.password.encode(),
        bcrypt.gensalt()
    ).decode()

    try:
        with connect() as db:
            db.execute(
                """INSERT INTO users
                (email,password,role,status)
                VALUES (?,?,?,?)""",
                (
                    data.email.lower(),
                    hashed,
                    "user",
                    "pending"
                )
            )
        return {"message": "Registration submitted for approval"}

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")

@app.post("/login")
def login(data: LoginData):
    with connect() as db:
        row = db.execute(
            "SELECT id,password,status FROM users WHERE email=?",
            (data.email.lower(),)
        ).fetchone()

    if not row or not bcrypt.checkpw(
        data.password.encode(),
        row[1].encode()
    ):
        raise HTTPException(401, "Invalid email or password")

    if row[2] != "approved":
        raise HTTPException(403, "Account awaiting admin approval")

    return {"access_token": make_token(row[0]), "token_type": "bearer"}

@app.get("/admin/users")
def list_users(admin=Depends(admin_only)):
    with connect() as db:
        rows = db.execute(
            "SELECT id,email,role,status FROM users ORDER BY id DESC"
        ).fetchall()

    return {
        "users": [
            {
                "id": r[0],
                "email": r[1],
                "role": r[2],
                "status": r[3]
            }
            for r in rows
        ]
    }

@app.post("/admin/approve/{user_id}")
def approve_user(user_id: int, admin=Depends(admin_only)):
    with connect() as db:
        result = db.execute(
            """UPDATE users SET status='approved'
            WHERE id=? AND role='user'""",
            (user_id,)
        )

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

    return {"message": "User approved"}
