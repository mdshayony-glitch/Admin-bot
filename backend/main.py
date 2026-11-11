
import os
import re
import time
import hmac
import hashlib
import secrets
import sqlite3
import base64
import html
from contextlib import contextmanager

import bcrypt
import requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

from indicators import analyze
from market_data import get_candles


# =========================
# CONFIGURATION
# =========================

APP_NAME = "Admin Bot Dashboard"
DB_PATH = os.getenv("DB_PATH", "admin.db")
SECRET_KEY = os.getenv("SECRET_KEY", "")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

SESSION_DURATION = 60 * 60 * 24 * 7

app = FastAPI(title=APP_NAME)


# =========================
# DATABASE
# =========================

@contextmanager
def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def audit(db, action, details=""):
    db.execute(
        """
        INSERT INTO audit_logs (action, details, created_at)
        VALUES (?, ?, ?)
        """,
        (action, details, int(time.time()))
    )


@app.on_event("startup")
def setup_database():

    with connect() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                last_seen INTEGER DEFAULT 0
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT DEFAULT '',
                created_at INTEGER NOT NULL
            )
        """)

        # Basic migration for an older users table
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "created_at" not in columns:
            db.execute("""
                ALTER TABLE users
                ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0
            """)

        if "last_seen" not in columns:
            db.execute("""
                ALTER TABLE users
                ADD COLUMN last_seen INTEGER DEFAULT 0
            """)

        # Create the first admin only when it does not exist
        if ADMIN_EMAIL and ADMIN_PASSWORD:

            existing = db.execute(
                "SELECT id FROM users WHERE email = ?",
                (ADMIN_EMAIL.lower(),)
            ).fetchone()

            if not existing:

                password_hash = bcrypt.hashpw(
                    ADMIN_PASSWORD.encode("utf-8"),
                    bcrypt.gensalt()
                ).decode("utf-8")

                db.execute("""
                    INSERT INTO users
                    (email, password_hash, role, status, created_at)
                    VALUES (?, ?, 'superadmin', 'approved', ?)
                """, (
                    ADMIN_EMAIL.lower(),
                    password_hash,
                    int(time.time())
                ))


# =========================
# REQUEST MODELS
# =========================

class RegisterData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class LoginData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class AdminCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


# =========================
# SECURITY
# =========================

def make_token(user_id):

    if len(SECRET_KEY) < 32:
        raise HTTPException(
            status_code=500,
            detail="SECRET_KEY must contain at least 32 characters"
        )

    random_part = secrets.token_urlsafe(32)

    message = f"{user_id}.{random_part}".encode()

    signature = hmac.new(
        SECRET_KEY.encode(),
        message,
        hashlib.sha256
    ).digest()

    token = base64.urlsafe_b64encode(
        message + b"." + signature
    ).decode()

    return token


def current_user(
    authorization: str = Header(default=None)
):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")

    token = authorization.replace("Bearer ", "", 1)

    with connect() as db:

        session = db.execute("""
            SELECT user_id, expires_at
            FROM sessions
            WHERE token = ?
        """, (token,)).fetchone()

        if not session:
            raise HTTPException(401, "Invalid session")

        if session["expires_at"] < int(time.time()):

            db.execute(
                "DELETE FROM sessions WHERE token = ?",
                (token,)
            )

            raise HTTPException(401, "Session expired")

        user = db.execute("""
            SELECT id, email, role, status, created_at, last_seen
            FROM users
            WHERE id = ?
        """, (session["user_id"],)).fetchone()

        if not user:
            raise HTTPException(401, "User not found")

        if user["status"] != "approved":
            raise HTTPException(403, "Account is not approved")

        db.execute(
            "UPDATE users SET last_seen = ? WHERE id = ?",
            (int(time.time()), user["id"])
        )

        return dict(user)


def admin_only(user=Depends(current_user)):

    if user["role"] not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin access required")

    return user


def super_admin_only(user=Depends(current_user)):

    if user["role"] != "superadmin":
        raise HTTPException(403, "Super admin access required")

    return user


# =========================
# MAIN ROUTES
# =========================

@app.get("/")
def home():

    return {
        "status": "online",
        "application": APP_NAME,
        "dashboard": "/admin/dashboard",
        "api_docs": "/docs"
    }


@app.get("/health")
def health():

    return {"status": "healthy"}


# =========================
# REGISTER
# =========================

@app.post("/register")
def register(data: RegisterData):

    email = data.email.lower()

    password_hash = bcrypt.hashpw(
        data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    with connect() as db:

        existing = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing:
            raise HTTPException(400, "Email already registered")

        db.execute("""
            INSERT INTO users
            (email, password_hash, role, status, created_at)
            VALUES (?, ?, 'user', 'pending', ?)
        """, (
            email,
            password_hash,
            int(time.time())
        ))

        audit(db, "USER_REGISTERED", email)

    return {
        "message": "Registration successful. Wait for admin approval."
    }


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(data: LoginData):

    email = data.email.lower()

    with connect() as db:

        user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if not user:
            raise HTTPException(401, "Invalid email or password")

        if not bcrypt.checkpw(
            data.password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        ):
            raise HTTPException(401, "Invalid email or password")

        if user["status"] != "approved":
            raise HTTPException(403, "Account is not approved")

        token = make_token(user["id"])

        db.execute("""
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (?, ?, ?)
        """, (
            token,
            user["id"],
            int(time.time()) + SESSION_DURATION
        ))

        db.execute(
            "UPDATE users SET last_seen = ? WHERE id = ?",
            (int(time.time()), user["id"])
        )

        audit(db, "LOGIN", email)

    return {
        "access_token": token,
        "token_type": "bearer",
        "message": "Login successful"
    }


# =========================
# LOGOUT
# =========================

@app.post("/logout")
def logout(
    authorization: str = Header(default=None)
):

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")

    token = authorization.replace("Bearer ", "", 1)

    with connect() as db:

        db.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

    return {"message": "Logged out"}


# =========================
# USER API
# =========================

@app.get("/admin/api/me")
def my_profile(user=Depends(current_user)):

    return user


@app.get("/admin/api/stats")
def stats(admin=Depends(admin_only)):

    with connect() as db:

        total = db.execute(
            "SELECT COUNT(*) AS n FROM users"
        ).fetchone()["n"]

        online = db.execute("""
            SELECT COUNT(*) AS n
            FROM users
            WHERE last_seen > ?
        """, (int(time.time()) - 300,)).fetchone()["n"]

        pending = db.execute("""
            SELECT COUNT(*) AS n
            FROM users
            WHERE status = 'pending'
        """).fetchone()["n"]

        blocked = db.execute("""
            SELECT COUNT(*) AS n
            FROM users
            WHERE status = 'blocked'
        """).fetchone()["n"]

    return {
        "total_users": total,
        "online_users": online,
        "pending_users": pending,
        "blocked_users": blocked
    }


@app.get("/admin/api/users")
def list_users(admin=Depends(admin_only)):

    with connect() as db:

        rows = db.execute("""
            SELECT id, email, role, status, created_at, last_seen
            FROM users
            ORDER BY id DESC
        """).fetchall()

    return [dict(row) for row in rows]


@app.post("/admin/api/users/{user_id}/approve")
def approve_user(
    user_id: int,
    admin=Depends(admin_only)
):

    with connect() as db:

        result = db.execute("""
            UPDATE users
            SET status = 'approved'
            WHERE id = ? AND role = 'user'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

        audit(db, "USER_APPROVED", str(user_id))

    return {"message": "User approved"}


@app.post("/admin/api/users/{user_id}/block")
def block_user(
    user_id: int,
    admin=Depends(admin_only)
):

    with connect() as db:

        result = db.execute("""
            UPDATE users
            SET status = 'blocked'
            WHERE id = ? AND role = 'user'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

        db.execute("""
            DELETE FROM sessions
            WHERE user_id = ?
        """, (user_id,))

        audit(db, "USER_BLOCKED", str(user_id))

    return {"message": "User blocked"}


@app.post("/admin/api/users/{user_id}/unblock")
def unblock_user(
    user_id: int,
    admin=Depends(admin_only)
):

    with connect() as db:

        result = db.execute("""
            UPDATE users
            SET status = 'approved'
            WHERE id = ? AND role = 'user'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "User not found")

        audit(db, "USER_UNBLOCKED", str(user_id))

    return {"message": "User unblocked"}


# =========================
# SUBADMIN MANAGEMENT
# =========================

@app.post("/admin/api/subadmins")
def create_subadmin(
    data: AdminCreate,
    admin=Depends(super_admin_only)
):

    email = data.email.lower()

    password_hash = bcrypt.hashpw(
        data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    with connect() as db:

        existing = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing:
            raise HTTPException(400, "Email already exists")

        db.execute("""
            INSERT INTO users
            (email, password_hash, role, status, created_at)
            VALUES (?, ?, 'admin', 'approved', ?)
        """, (
            email,
            password_hash,
            int(time.time())
        ))

        audit(db, "SUBADMIN_CREATED", email)

    return {"message": "Subadmin created"}


@app.get("/admin/api/subadmins")
def list_subadmins(admin=Depends(super_admin_only)):

    with connect() as db:

        rows = db.execute("""
            SELECT id, email, role, status, created_at
            FROM users
            WHERE role = 'admin'
            ORDER BY id DESC
        """).fetchall()

    return [dict(row) for row in rows]


@app.post("/admin/api/subadmins/{user_id}/disable")
def disable_subadmin(
    user_id: int,
    admin=Depends(super_admin_only)
):

    with connect() as db:

        result = db.execute("""
            UPDATE users
            SET status = 'blocked'
            WHERE id = ? AND role = 'admin'
        """, (user_id,))

        if result.rowcount == 0:
            raise HTTPException(404, "Subadmin not found")

        db.execute(
            "DELETE FROM sessions WHERE user_id = ?",
            (user_id,)
        )

        audit(db, "SUBADMIN_DISABLED", str(user_id))

    return {"message": "Subadmin disabled"}


# =========================
# AUDIT LOGS
# =========================

@app.get("/admin/api/logs")
def get_logs(admin=Depends(admin_only)):

    with connect() as db:

        rows = db.execute("""
            SELECT id, action, details, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return [dict(row) for row in rows]


# =========================
# MARKET ANALYSIS API
# =========================

@app.get("/admin/api/market-analysis")
def market_analysis(
    symbol: str = "BTCUSDT",
    interval: str = "1m",
    admin=Depends(admin_only)
):

    symbol = symbol.upper().strip()

    if not re.fullmatch(r"[A-Z0-9]{5,20}", symbol):
        raise HTTPException(400, "Invalid market symbol")

    try:

        candles = get_candles(
            symbol=symbol,
            interval=interval,
            limit=100
        )

        closes = [candle["close"] for candle in candles]

        indicators = analyze(closes)

        return {
            "market": symbol,
            "timeframe": interval,
            "provider": "Binance Public API",
            "candles": candles,
            "indicators": indicators,
            "notice": (
                "Historical market analysis only. "
                "This is not a future price prediction or trading signal."
            )
        }

    except ValueError as error:
        raise HTTPException(400, str(error))

    except requests.RequestException:
        raise HTTPException(
            502,
            "Market data provider is temporarily unavailable"
        )


# =========================
# ADMIN DASHBOARD HTML
# =========================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Dashboard</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 18px;
    background: #10131d;
    color: #ffffff;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1, h2 {
    color: #e9edff;
}

.card {
    background: #1b2030;
    border: 1px solid #30394e;
    border-radius: 12px;
    padding: 16px;
    margin: 14px 0;
}

input, select {
    width: 100%;
    padding: 12px;
    margin: 7px 0;
    border: 1px solid #46516b;
    border-radius: 7px;
    background: #101624;
    color: white;
}

button {
    padding: 10px 14px;
    margin: 5px 3px;
    border: 0;
    border-radius: 7px;
    background: #3867f5;
    color: white;
    cursor: pointer;
}

button.danger {
    background: #bd3d50;
}

button.success {
    background: #16875c;
}

.stats {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
}

.stat {
    background: #252d42;
    padding: 15px;
    border-radius: 10px;
}

.stat strong {
    display: block;
    font-size: 24px;
    margin-top: 8px;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 600px;
}

td, th {
    border-bottom: 1px solid #354057;
    padding: 10px;
    text-align: left;
}

small {
    color: #aeb8ce;
}

.hidden {
    display: none;
}

pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    color: #c6d5ff;
}

#message {
    color: #8ce0b1;
    margin: 10px 0;
}

@media(min-width:700px) {
    .stats {
        grid-template-columns: repeat(4, 1fr);
    }
}
</style>
</head>

<body>

<div class="container">

<h1>Admin Dashboard</h1>
<div id="message"></div>

<div class="card" id="loginBox">
    <h2>Admin Login</h2>

    <input id="loginEmail" type="email"
        placeholder="Admin email">

    <input id="loginPassword" type="password"
        placeholder="Password">

    <button onclick="login()">Login</button>
</div>

<div id="dashboard" class="hidden">

    <div class="card">
        <div id="profile"></div>
        <button onclick="logout()">Logout</button>
        <button onclick="loadAll()">Refresh</button>
    </div>

    <h2>Overview</h2>

    <div class="stats">
        <div class="stat">
            Total Users
            <strong id="total">0</strong>
        </div>

        <div class="stat">
            Online
            <strong id="online">0</strong>
        </div>

        <div class="stat">
            Pending
            <strong id="pending">0</strong>
        </div>

        <div class="stat">
            Blocked
            <strong id="blocked">0</strong>
        </div>
    </div>

    <div class="card">
        <h2>User Management</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="users"></tbody>
            </table>
        </div>
    </div>

    <div class="card" id="subadminBox">
        <h2>Create Subadmin</h2>

        <input id="subEmail" type="email"
            placeholder="Subadmin email">

        <input id="subPassword" type="password"
            placeholder="Subadmin password">

        <button onclick="createSubadmin()">Create</button>

        <h3>Subadmins</h3>
        <div id="subadmins"></div>
    </div>

    <div class="card">
        <h2>Market Analysis</h2>

        <small>
            Public historical Binance data. Not Quotex or OTC data.
            This section does not generate future trading signals.
        </small>

        <input id="marketSymbol"
            value="BTCUSDT"
            placeholder="Example: BTCUSDT">

        <select id="marketInterval">
            <option value="1m">1 minute</option>
            <option value="5m">5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="30m">30 minutes</option>
            <option value="1h">1 hour</option>
            <option value="4h">4 hours</option>
            <option value="1d">1 day</option>
        </select>

        <button onclick="loadMarket()">Analyze Market</button>

        <pre id="marketResult">No analysis loaded.</pre>
    </div>

    <div class="card">
        <h2>Recent Activity Logs</h2>
        <div id="logs"></div>
    </div>

</div>
</div>

<script>
let token = localStorage.getItem("admin_token") || "";

function el(id) {
    return document.getElementById(id);
}

function showMessage(message) {
    el("message").textContent = message;
}

async function api(path, method="GET", body=null) {

    const headers = {};

    if (token) {
        headers["Authorization"] = "Bearer " + token;
    }

    if (body !== null) {
        headers["Content-Type"] = "application/json";
    }

    const response = await fetch(path, {
        method: method,
        headers: headers,
        body: body === null ? null : JSON.stringify(body)
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.detail || "Request failed");
    }

    return data;
}

async function login() {

    try {

        const email = el("loginEmail").value;
        const password = el("loginPassword").value;

        const data = await api("/login", "POST", {
            email: email,
            password: password
        });

        token = data.access_token;

        localStorage.setItem("admin_token", token);

        showMessage("Login successful");

        await loadAll();

    } catch (error) {
        showMessage(error.message);
    }
}

async function logout() {

    try {
        await api("/logout", "POST");
    } catch (error) {
        // Clear local session even if server logout fails
    }

    token = "";
    localStorage.removeItem("admin_token");

    el("dashboard").classList.add("hidden");
    el("loginBox").classList.remove("hidden");

    showMessage("Logged out");
}

async function loadAll() {

    try {

        const me = await api("/admin/api/me");

        if (!["admin", "superadmin"].includes(me.role)) {
            throw new Error("Admin access required");
        }

        el("loginBox").classList.add("hidden");
        el("dashboard").classList.remove("hidden");

        el("profile").textContent =
            me.email + " | " + me.role;

        const data = await api("/admin/api/stats");

        el("total").textContent = data.total_users;
        el("online").textContent = data.online_users;
        el("pending").textContent = data.pending_users;
        el("blocked").textContent = data.blocked_users;

        await loadUsers();
        await loadLogs();

        if (me.role === "superadmin") {
            el("subadminBox").classList.remove("hidden");
            await loadSubadmins();
        } else {
            el("subadminBox").classList.add("hidden");
        }

    } catch (error) {

        token = "";
        localStorage.removeItem("admin_token");

        el("dashboard").classList.add("hidden");
        el("loginBox").classList.remove("hidden");

        showMessage(error.message);
    }
}

async function loadUsers() {

    const users = await api("/admin/api/users");

    const tbody = el("users");
    tbody.innerHTML = "";

    users.forEach(user => {

        const tr = document.createElement("tr");

        const values = [
            user.id,
            user.email,
            user.role,
            user.status
        ];

        values.forEach(value => {
            const td = document.createElement("td");
            td.textContent = value;
            tr.appendChild(td);
        });

        const action = document.createElement("td");

        if (user.role === "user") {

            if (user.status === "pending") {
                action.appendChild(
                    makeButton("Approve", "success",
                        () => userAction(user.id, "approve"))
                );
            }

            if (user.status === "approved") {
                action.appendChild(
                    makeButton("Block", "danger",
                        () => userAction(user.id, "block"))
                );
            }

            if (user.status === "blocked") {
                action.appendChild(
                    makeButton("Unblock", "success",
                        () => userAction(user.id, "unblock"))
                );
            }
        }

        tr.appendChild(action);
        tbody.appendChild(tr);
    });
}

function makeButton(label, style, callback) {

    const button = document.createElement("button");

    button.textContent = label;

    if (style) {
        button.className = style;
    }

    button.onclick = callback;

    return button;
}

async function userAction(id, action) {

    try {

        await api(
            "/admin/api/users/" + id + "/" + action,
            "POST"
        );

        showMessage("User updated");

        await loadAll();

    } catch (error) {
        showMessage(error.message);
    }
}

async function createSubadmin() {

    try {

        await api("/admin/api/subadmins", "POST", {
            email: el("subEmail").value,
            password: el("subPassword").value
        });

        el("subEmail").value = "";
        el("subPassword").value = "";

        showMessage("Subadmin created");

        await loadSubadmins();

    } catch (error) {
        showMessage(error.message);
    }
}

async function loadSubadmins() {

    const admins = await api("/admin/api/subadmins");

    const box = el("subadmins");
    box.innerHTML = "";

    admins.forEach(admin => {

        const row = document.createElement("div");

        row.textContent =
            admin.email + " — " + admin.status + " ";

        if (admin.status !== "blocked") {

            row.appendChild(
                makeButton("Disable", "danger", async () => {

                    try {

                        await api(
                            "/admin/api/subadmins/" +
                            admin.id + "/disable",
                            "POST"
                        );

                        showMessage("Subadmin disabled");

                        await loadSubadmins();

                    } catch (error) {
                        showMessage(error.message);
                    }
                })
            );
        }

        box.appendChild(row);
    });
}

async function loadLogs() {

    const logs = await api("/admin/api/logs");

    const box = el("logs");
    box.innerHTML = "";

    logs.forEach(log => {

        const row = document.createElement("p");

        row.textContent =
            "#" + log.id + " | " +
            log.action + " | " +
            log.details + " | " +
            new Date(log.created_at * 1000).toLocaleString();

        box.appendChild(row);
    });
}

async function loadMarket() {

    const symbol = encodeURIComponent(
        el("marketSymbol").value.trim()
    );

    const interval = encodeURIComponent(
        el("marketInterval").value
    );

    el("marketResult").textContent = "Loading market data...";

    try {

        const data = await api(
            "/admin/api/market-analysis?symbol=" +
            symbol + "&interval=" + interval
        );

        el("marketResult").textContent =
            JSON.stringify(data, null, 2);

    } catch (error) {

        el("marketResult").textContent =
            "Error: " + error.message;
    }
}

if (token) {
    loadAll();
}
</script>

</body>
</html>
"""


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():

    return HTMLResponse(DASHBOARD_HTML)


@app.get("/dashboard")
def user_dashboard():
    from pathlib import Path
    file = Path(__file__).resolve().parent / "dashboard.html"
    return FileResponse(str(file))
