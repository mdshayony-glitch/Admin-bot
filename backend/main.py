import os
import sqlite3
import bcrypt
import hmac
import hashlib
import base64
import time
import secrets
import html

from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field

app = FastAPI(title="Admin Bot Dashboard")
security = HTTPBearer(auto_error=False)

DB = os.getenv("DATABASE_PATH", "bot.db")
SECRET = os.getenv("SECRET_KEY", "")

ONLINE_SECONDS = 300


@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def audit(db, admin_id, action, target=""):
    db.execute(
        """INSERT INTO audit_logs(admin_id,action,target,created_at)
        VALUES(?,?,?,?)""",
        (admin_id, action, str(target), int(time.time()))
    )


@app.on_event("startup")
def setup():
    with connect() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS sessions(
            token_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
        )
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT NOT NULL,
            target TEXT,
            created_at INTEGER NOT NULL
        )
        """)

        email = os.getenv("ADMIN_EMAIL", "").lower().strip()
        password = os.getenv("ADMIN_PASSWORD", "")

        if email and password:
            exists = db.execute(
                "SELECT id FROM users WHERE email=?", (email,)
            ).fetchone()

            if not exists:
                hashed = bcrypt.hashpw(
                    password.encode(), bcrypt.gensalt()
                ).decode()

                db.execute(
                    """INSERT INTO users
                    (email,password,role,status,created_at)
                    VALUES(?,?,?,?,?)""",
                    (email, hashed, "super_admin",
                     "approved", int(time.time()))
                )


class RegisterData(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)


class LoginData(BaseModel):
    email: EmailStr
    password: str


class AdminCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)


def make_token(user_id):
    if not SECRET or len(SECRET) < 32:
        raise HTTPException(500, "SECRET_KEY must be at least 32 characters")

    expiry = int(time.time()) + 86400
    token_id = secrets.token_urlsafe(24)
    payload = f"{user_id}:{expiry}:{token_id}"

    signature = hmac.new(
        SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    token = base64.urlsafe_b64encode(
        f"{payload}:{signature}".encode()
    ).decode()

    with connect() as db:
        db.execute(
            """INSERT INTO sessions
            (token_id,user_id,expires_at,last_seen)
            VALUES(?,?,?,?)""",
            (token_id, user_id, expiry, int(time.time()))
        )

    return token


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if not credentials:
        raise HTTPException(401, "Please login")

    try:
        decoded = base64.urlsafe_b64decode(
            credentials.credentials.encode()
        ).decode()

        user_id, expiry, token_id, signature = decoded.split(":")
        payload = f"{user_id}:{expiry}:{token_id}"

        expected = hmac.new(
            SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        if not SECRET or not hmac.compare_digest(signature, expected):
            raise ValueError()

        if int(expiry) < int(time.time()):
            raise ValueError()

        with connect() as db:
            session = db.execute(
                """SELECT user_id FROM sessions
                WHERE token_id=? AND user_id=? AND expires_at>=?""",
                (token_id, int(user_id), int(time.time()))
            ).fetchone()

            row = db.execute(
                "SELECT id,email,role,status FROM users WHERE id=?",
                (int(user_id),)
            ).fetchone()

            if not session or not row or row["status"] != "approved":
                raise ValueError()

            db.execute(
                "UPDATE sessions SET last_seen=? WHERE token_id=?",
                (int(time.time()), token_id)
            )

        return {
            "id": row["id"],
            "email": row["email"],
            "role": row["role"],
            "token_id": token_id
        }

    except Exception:
        raise HTTPException(401, "Invalid or expired login")


def admin_only(user=Depends(current_user)):
    if user["role"] not in ("super_admin", "sub_admin"):
        raise HTTPException(403, "Admin access required")
    return user


def super_admin_only(user=Depends(current_user)):
    if user["role"] != "super_admin":
        raise HTTPException(403, "Super Admin access required")
    return user


@app.get("/")
def home():
    return {
        "status": "online",
        "application": "Admin Bot Dashboard",
        "dashboard": "/admin/dashboard",
        "api_docs": "/docs"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/register")
def register(data: RegisterData):
    email = str(data.email).lower().strip()

    hashed = bcrypt.hashpw(
        data.password.encode(), bcrypt.gensalt()
    ).decode()

    try:
        with connect() as db:
            db.execute(
                """INSERT INTO users
                (email,password,role,status,created_at)
                VALUES(?,?,?,?,?)""",
                (email, hashed, "user", "pending", int(time.time()))
            )

        return {"message": "Registration submitted for approval"}

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")


@app.post("/login")
def login(data: LoginData):
    with connect() as db:
        row = db.execute(
            "SELECT id,password,status FROM users WHERE email=?",
            (str(data.email).lower().strip(),)
        ).fetchone()

    if not row or not bcrypt.checkpw(
        data.password.encode(), row["password"].encode()
    ):
        raise HTTPException(401, "Invalid email or password")

    if row["status"] == "blocked":
        raise HTTPException(403, "Account blocked")

    if row["status"] != "approved":
        raise HTTPException(403, "Waiting for admin approval")

    token = make_token(row["id"])
    return {"access_token": token, "token_type": "bearer"}


@app.post("/logout")
def logout(user=Depends(current_user)):
    with connect() as db:
        db.execute(
            "DELETE FROM sessions WHERE token_id=?",
            (user["token_id"],)
        )
    return {"message": "Logged out"}


@app.get("/admin/dashboard", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/admin/api/me")
def admin_me(admin=Depends(admin_only)):
    return {
        "email": admin["email"],
        "role": admin["role"]
    }


@app.get("/admin/api/stats")
def stats(admin=Depends(admin_only)):
    now = int(time.time())

    with connect() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        pending = db.execute(
            "SELECT COUNT(*) FROM users WHERE status='pending'"
        ).fetchone()[0]

        blocked = db.execute(
            "SELECT COUNT(*) FROM users WHERE status='blocked'"
        ).fetchone()[0]

        online = db.execute(
            """SELECT COUNT(DISTINCT user_id) FROM sessions
            WHERE last_seen>=? AND expires_at>=?""",
            (now - ONLINE_SECONDS, now)
        ).fetchone()[0]

    return {
        "total_users": total,
        "pending_users": pending,
        "blocked_users": blocked,
        "online_users": online
    }


@app.get("/admin/api/users")
def list_users(admin=Depends(admin_only)):
    with connect() as db:
        rows = db.execute(
            """SELECT id,email,role,status,created_at
            FROM users ORDER BY id DESC"""
        ).fetchall()

    return {"users": [dict(row) for row in rows]}


@app.post("/admin/api/users/{user_id}/approve")
def approve_user(user_id: int, admin=Depends(admin_only)):
    with connect() as db:
        result = db.execute(
            """UPDATE users SET status='approved'
            WHERE id=? AND role='user' AND status='pending'""",
            (user_id,)
        )

        if result.rowcount == 0:
            raise HTTPException(404, "Pending user not found")

        audit(db, admin["id"], "APPROVE_USER", user_id)

    return {"message": "User approved"}


@app.post("/admin/api/users/{user_id}/block")
def block_user(user_id: int, admin=Depends(admin_only)):
    with connect() as db:
        row = db.execute(
            "SELECT role FROM users WHERE id=?", (user_id,)
        ).fetchone()

        if not row or row["role"] != "user":
            raise HTTPException(404, "Regular user not found")

        db.execute(
            "UPDATE users SET status='blocked' WHERE id=?",
            (user_id,)
        )
        db.execute(
            "DELETE FROM sessions WHERE user_id=?", (user_id,)
        )
        audit(db, admin["id"], "BLOCK_USER", user_id)

    return {"message": "User blocked"}


@app.post("/admin/api/users/{user_id}/unblock")
def unblock_user(user_id: int, admin=Depends(admin_only)):
    with connect() as db:
        result = db.execute(
            """UPDATE users SET status='approved'
            WHERE id=? AND role='user' AND status='blocked'""",
            (user_id,)
        )

        if result.rowcount == 0:
            raise HTTPException(404, "Blocked user not found")

        audit(db, admin["id"], "UNBLOCK_USER", user_id)

    return {"message": "User unblocked"}


@app.post("/admin/api/subadmins")
def create_subadmin(
    data: AdminCreate,
    admin=Depends(super_admin_only)
):
    email = str(data.email).lower().strip()
    hashed = bcrypt.hashpw(
        data.password.encode(), bcrypt.gensalt()
    ).decode()

    try:
        with connect() as db:
            db.execute(
                """INSERT INTO users
                (email,password,role,status,created_at)
                VALUES(?,?,?,?,?)""",
                (email, hashed, "sub_admin",
                 "approved", int(time.time()))
            )
            audit(db, admin["id"], "CREATE_SUBADMIN", email)

        return {"message": "Sub Admin created"}

    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")


@app.get("/admin/api/subadmins")
def list_subadmins(admin=Depends(super_admin_only)):
    with connect() as db:
        rows = db.execute(
            """SELECT id,email,status,created_at
            FROM users WHERE role='sub_admin'
            ORDER BY id DESC"""
        ).fetchall()

    return {"subadmins": [dict(row) for row in rows]}


@app.post("/admin/api/subadmins/{user_id}/disable")
def disable_subadmin(
    user_id: int,
    admin=Depends(super_admin_only)
):
    with connect() as db:
        result = db.execute(
            """UPDATE users SET status='blocked'
            WHERE id=? AND role='sub_admin'""",
            (user_id,)
        )

        if result.rowcount == 0:
            raise HTTPException(404, "Sub Admin not found")

        db.execute(
            "DELETE FROM sessions WHERE user_id=?", (user_id,)
        )
        audit(db, admin["id"], "DISABLE_SUBADMIN", user_id)

    return {"message": "Sub Admin disabled"}


@app.get("/admin/api/logs")
def logs(admin=Depends(super_admin_only)):
    with connect() as db:
        rows = db.execute(
            """SELECT id,admin_id,action,target,created_at
            FROM audit_logs ORDER BY id DESC LIMIT 100"""
        ).fetchall()

    return {"logs": [dict(row) for row in rows]}


DASHBOARD_HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0d1320;color:#eef3ff;font-family:Arial,sans-serif}
header{padding:20px;background:#151f32;font-size:22px;font-weight:bold}
main{max-width:950px;margin:auto;padding:16px}
.card{background:#18243a;padding:17px;border-radius:12px;margin:12px 0}
input,button{padding:12px;border-radius:8px;border:1px solid #43516b;margin:5px 0}
input{background:#0d1320;color:white;width:100%}
button{background:#315eea;color:white;border:0;cursor:pointer}
button.red{background:#b83b48}
button.green{background:#17895c}
button.gray{background:#526078}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.num{font-size:27px;font-weight:bold;margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:9px;border-bottom:1px solid #34435c;text-align:left}
.tablewrap{overflow-x:auto}
.small{font-size:12px;color:#b9c6da}
.hidden{display:none}
#message{color:#ffd37b}
</style>
</head>
<body>
<header>ADMIN DASHBOARD</header>
<main>
<div class="card" id="loginBox">
<h3>Admin Login</h3>
<input id="email" type="email" placeholder="Admin email">
<input id="password" type="password" placeholder="Admin password">
<button onclick="login()">Login</button>
<p id="message"></p>
</div>

<div id="panel" class="hidden">
<div class="card">
<div id="who"></div>
<button class="gray" onclick="refreshAll()">Refresh</button>
<button class="red" onclick="logout()">Logout</button>
</div>

<div class="stats">
<div class="card">Total Users<div class="num" id="total">0</div></div>
<div class="card">Online Now<div class="num" id="online">0</div></div>
<div class="card">Pending<div class="num" id="pending">0</div></div>
<div class="card">Blocked<div class="num" id="blocked">0</div></div>
</div>

<div class="card">
<h3>All Users</h3>
<div class="tablewrap">
<table>
<thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
<tbody id="users"></tbody>
</table>
</div>
</div>

<div class="card" id="subadminBox">
<h3>Create Sub Admin</h3>
<input id="subEmail" type="email" placeholder="Sub Admin email">
<input id="subPassword" type="password" placeholder="Temporary password (12+ characters)">
<button onclick="createSubadmin()">Create Sub Admin</button>
<h3>Sub Admin List</h3>
<div id="subadmins"></div>
</div>

<div class="card" id="logsBox">
<h3>Recent Admin Activity</h3>
<div id="logs"></div>
</div>
<p class="small">Online means activity within the last 5 minutes. This is a basic activity indicator, not proof that a person is actively viewing the page.</p>
</div>
</main>

<script>
let token = sessionStorage.getItem("admin_token") || "";
let role = "";

async function api(path,method="GET",body=null){
 const options={method,headers:{}};
 if(token) options.headers.Authorization="Bearer "+token;
 if(body){
  options.headers["Content-Type"]="application/json";
  options.body=JSON.stringify(body);
 }
 const response=await fetch("/admin/api"+path,options);
 const data=await response.json().catch(()=>({detail:"Server response error"}));
 if(!response.ok) throw new Error(data.detail || "Request failed");
 return data;
}

async function login(){
 const email=document.getElementById("email").value;
 const password=document.getElementById("password").value;
 try{
  const response=await fetch("/login",{
   method:"POST",
   headers:{"Content-Type":"application/json"},
   body:JSON.stringify({email,password})
  });
  const data=await response.json();
  if(!response.ok) throw new Error(data.detail || "Login failed");
  token=data.access_token;
  sessionStorage.setItem("admin_token",token);
  await startPanel();
 }catch(e){document.getElementById("message").textContent=e.message;}
}

async function startPanel(){
 try{
  const me=await api("/me");
  role=me.role;
  document.getElementById("who").textContent=me.email+" — "+role;
  document.getElementById("loginBox").classList.add("hidden");
  document.getElementById("panel").classList.remove("hidden");
  if(role!=="super_admin"){
   document.getElementById("subadminBox").classList.add("hidden");
   document.getElementById("logsBox").classList.add("hidden");
  }
  await refreshAll();
 }catch(e){
  sessionStorage.removeItem("admin_token");
  token="";
  document.getElementById("message").textContent="Please login again";
 }
}

async function refreshAll(){
 try{
  const s=await api("/stats");
  total.textContent=s.total_users;
  online.textContent=s.online_users;
  pending.textContent=s.pending_users;
  blocked.textContent=s.blocked_users;
  const data=await api("/users");
  users.innerHTML="";
  data.users.forEach(u=>{
   const tr=document.createElement("tr");
   [u.id,u.email,u.role,u.status].forEach(v=>{
    const td=document.createElement("td");
    td.textContent=v;
    tr.appendChild(td);
   });
   const action=document.createElement("td");
   if(u.role==="user"){
    if(u.status==="pending"){
     action.appendChild(makeButton("Approve","green",()=>act(u.id,"approve")));
    }else if(u.status==="blocked"){
     action.appendChild(makeButton("Unblock","green",()=>act(u.id,"unblock")));
    }else{
     action.appendChild(makeButton("Block","red",()=>act(u.id,"block")));
    }
   }
   tr.appendChild(action);
   users.appendChild(tr);
  });
  if(role==="super_admin"){
   const a=await api("/subadmins");
   subadmins.innerHTML="";
   a.subadmins.forEach(u=>{
    const p=document.createElement("p");
    p.textContent=u.email+" — "+u.status+" ";
    if(u.status!=="blocked"){
     p.appendChild(makeButton("Disable","red",()=>disableSub(u.id)));
    }
    subadmins.appendChild(p);
   });
   const l=await api("/logs");
   logs.innerHTML="";
   l.logs.forEach(x=>{
    const p=document.createElement("p");
    p.textContent=x.action+" — "+x.target+" — "+new Date(x.created_at*1000).toLocaleString();
    logs.appendChild(p);
   });
  }
 }catch(e){alert(e.message);}
}

function makeButton(label,cls,fn){
 const b=document.createElement("button");
 b.textContent=label;b.className=cls;b.onclick=fn;return b;
}

async function act(id,action){
 if(!confirm("Are you sure?")) return;
 try{await api("/users/"+id+"/"+action,"POST");await refreshAll();}
 catch(e){alert(e.message);}
}

async function createSubadmin(){
 try{
  await api("/subadmins","POST",{
   email:subEmail.value,password:subPassword.value
  });
  subEmail.value="";subPassword.value="";
  alert("Sub Admin created");
  await refreshAll();
 }catch(e){alert(e.message);}
}

async function disableSub(id){
 if(!confirm("Disable this Sub Admin?")) return;
 try{await api("/subadmins/"+id+"/disable","POST");await refreshAll();}
 catch(e){alert(e.message);}
}

async function logout(){
 try{
  await fetch("/logout",{method:"POST",headers:{Authorization:"Bearer "+token}});
 }catch(e){}
 sessionStorage.removeItem("admin_token");
 token="";
 location.reload();
}

if(token) startPanel();
</script>
</body>
</html>
"""