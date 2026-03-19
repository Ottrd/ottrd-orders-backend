from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3, os, json, shutil, hashlib, secrets
from datetime import datetime, date, timedelta
from typing import Optional
import jwt

app = FastAPI(title="Ottrd Orders API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, "orders.db")
FILES_DIR = os.path.join(BASE_DIR, "order_files")
os.makedirs(FILES_DIR, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", "ottrd-secret-change-this")
bearer     = HTTPBearer()

# ── Auth helpers ───────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token(username: str) -> str:
    payload = {"sub": username, "exp": datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ── DB init ────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor TEXT NOT NULL, po_number TEXT, description TEXT,
        total_amount REAL DEFAULT 0, deposit_paid REAL DEFAULT 0, balance_due REAL DEFAULT 0,
        order_date TEXT, expected_arrival TEXT, actual_arrival TEXT,
        status TEXT DEFAULT 'Target', notes TEXT,
        created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS order_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL, filename TEXT NOT NULL,
        original_name TEXT, file_type TEXT,
        uploaded_by TEXT,
        uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id)
    )""")
    # Create default admin user if no users exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "ottrd2024")
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  ("admin", hash_password(admin_pw)))
    conn.commit()
    conn.close()

init_db()

# ── Auth routes ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "Ottrd Orders API"}

@app.post("/auth/login")
def login(data: dict):
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if not user or user["password_hash"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": make_token(username), "username": username}

@app.post("/auth/create-user")
def create_user(data: dict, username: str = Depends(verify_token)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create users")
    new_user = data.get("username", "").strip().lower()
    new_pass = data.get("password", "")
    if not new_user or not new_pass:
        raise HTTPException(status_code=400, detail="Username and password required")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                  (new_user, hash_password(new_pass)))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()
    return {"message": f"User '{new_user}' created"}

@app.get("/auth/users")
def list_users(username: str = Depends(verify_token)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, created_at FROM users ORDER BY username")
    users = [{"username": r[0], "created_at": r[1]} for r in c.fetchall()]
    conn.close()
    return users

@app.delete("/auth/users/{target}")
def delete_user(target: str, username: str = Depends(verify_token)):
    if username != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    if target == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (target,))
    conn.commit()
    conn.close()
    return {"message": f"User '{target}' deleted"}

# ── Orders ─────────────────────────────────────────────────────────────────────

def row_to_dict(row):
    return dict(row) if row else None

@app.get("/orders")
def get_orders(
    status: Optional[str] = None,
    vendor: Optional[str] = None,
    search: Optional[str] = None,
    username: str = Depends(verify_token)
):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    q = "SELECT * FROM orders WHERE 1=1"
    p = []
    if status and status != "All": q += " AND status=?"; p.append(status)
    if vendor and vendor != "All Vendors": q += " AND vendor=?"; p.append(vendor)
    if search: q += " AND (vendor LIKE ? OR po_number LIKE ? OR description LIKE ?)"; p.extend([f"%{search}%"]*3)
    q += """ ORDER BY CASE status
        WHEN 'Confirmed' THEN 1 WHEN 'Submitted' THEN 2
        WHEN 'Pending' THEN 3 WHEN 'Target' THEN 4 WHEN 'Arrived' THEN 5
        END, expected_arrival ASC"""
    c.execute(q, p)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

@app.get("/orders/stats")
def get_stats(username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    stats = {}
    for key, q in [
        ("total_open",     "SELECT SUM(total_amount) FROM orders WHERE status!='Arrived'"),
        ("total_deposits", "SELECT SUM(deposit_paid) FROM orders WHERE status!='Arrived'"),
        ("total_balance",  "SELECT SUM(balance_due)  FROM orders WHERE status!='Arrived'"),
    ]:
        c.execute(q); stats[key] = round(c.fetchone()[0] or 0, 2)
    for s in ["Target","Pending","Submitted","Confirmed","Arrived"]:
        c.execute("SELECT COUNT(*) FROM orders WHERE status=?", (s,))
        stats[f"count_{s}"] = c.fetchone()[0]
    today = date.today()
    in7   = (today + timedelta(days=7)).isoformat()
    c.execute("SELECT COUNT(*) FROM orders WHERE status!='Arrived' AND expected_arrival<=? AND expected_arrival>=?", (in7, today.isoformat()))
    stats["arriving_soon"] = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM orders WHERE status!='Arrived' AND expected_arrival<? AND expected_arrival!=''", (today.isoformat(),))
    stats["late"] = c.fetchone()[0]
    conn.close()
    return stats

@app.get("/orders/vendors")
def get_vendors(username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT vendor,
        COUNT(*) as order_count,
        SUM(total_amount) as total,
        SUM(deposit_paid) as deposits,
        SUM(balance_due) as balance,
        SUM(CASE WHEN status='Confirmed' THEN total_amount ELSE 0 END) as confirmed,
        SUM(CASE WHEN status='Submitted' THEN total_amount ELSE 0 END) as submitted,
        SUM(CASE WHEN status='Target' THEN total_amount ELSE 0 END) as target,
        SUM(CASE WHEN status='Pending' THEN total_amount ELSE 0 END) as pending
        FROM orders WHERE status!='Arrived' GROUP BY vendor ORDER BY total DESC""")
    rows = [dict(zip([d[0] for d in c.description], r)) for r in c.fetchall()]
    conn.close()
    return rows

@app.get("/orders/brands")
def get_brands(username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT description as brand,
        COUNT(*) as order_count,
        SUM(total_amount) as total,
        SUM(CASE WHEN status='Confirmed' THEN total_amount ELSE 0 END) as confirmed,
        SUM(CASE WHEN status='Submitted' THEN total_amount ELSE 0 END) as submitted,
        SUM(CASE WHEN status='Target' THEN total_amount ELSE 0 END) as target,
        SUM(CASE WHEN status='Arrived' THEN 1 ELSE 0 END) as arrived_count
        FROM orders WHERE description!='' AND description IS NOT NULL
        GROUP BY description ORDER BY total DESC""")
    rows = [dict(zip([d[0] for d in c.description], r)) for r in c.fetchall()]
    conn.close()
    return rows

@app.get("/orders/alerts")
def get_alerts(username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    today = date.today()
    alerts = []
    c.execute("SELECT vendor,po_number,expected_arrival FROM orders WHERE status!='Arrived' AND expected_arrival<? AND expected_arrival!=''", (today.isoformat(),))
    for r in c.fetchall():
        d = (today - date.fromisoformat(r["expected_arrival"])).days
        alerts.append({"type":"late","message":f"LATE ({d}d): {r['vendor']} — {r['po_number'] or 'No PO'} was due {r['expected_arrival']}"})
    in3 = (today + timedelta(days=3)).isoformat()
    c.execute("SELECT vendor,po_number,expected_arrival FROM orders WHERE status!='Arrived' AND expected_arrival<=? AND expected_arrival>=?", (in3, today.isoformat()))
    for r in c.fetchall():
        d = (date.fromisoformat(r["expected_arrival"]) - today).days
        alerts.append({"type":"soon","message":f"Arriving in {d}d: {r['vendor']} — {r['po_number'] or 'No PO'} on {r['expected_arrival']}"})
    conn.close()
    return alerts

@app.post("/orders")
def create_order(data: dict, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    total = float(data.get("total_amount") or 0)
    dep   = float(data.get("deposit_paid") or 0)
    c.execute("""INSERT INTO orders (vendor,po_number,description,total_amount,deposit_paid,
        balance_due,order_date,expected_arrival,actual_arrival,status,notes,created_by,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (data.get("vendor"), data.get("po_number",""), data.get("description",""),
         total, dep, round(total-dep,2),
         data.get("order_date",""), data.get("expected_arrival",""), "",
         data.get("status","Target"), data.get("notes",""), username, now, now))
    order_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": order_id, "message": "Order created"}

@app.put("/orders/{order_id}")
def update_order(order_id: int, data: dict, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now   = datetime.now().isoformat()
    total = float(data.get("total_amount") or 0)
    dep   = float(data.get("deposit_paid") or 0)
    c.execute("""UPDATE orders SET vendor=?,po_number=?,description=?,total_amount=?,
        deposit_paid=?,balance_due=?,order_date=?,expected_arrival=?,actual_arrival=?,
        status=?,notes=?,updated_at=? WHERE id=?""",
        (data.get("vendor"), data.get("po_number",""), data.get("description",""),
         total, dep, round(total-dep,2),
         data.get("order_date",""), data.get("expected_arrival",""),
         data.get("actual_arrival",""), data.get("status","Target"),
         data.get("notes",""), now, order_id))
    conn.commit()
    conn.close()
    return {"message": "Order updated"}

@app.patch("/orders/{order_id}/arrived")
def mark_arrived(order_id: int, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE orders SET status='Arrived',actual_arrival=?,updated_at=? WHERE id=?",
              (date.today().isoformat(), datetime.now().isoformat(), order_id))
    conn.commit()
    conn.close()
    return {"message": "Marked as arrived"}

@app.delete("/orders/{order_id}")
def delete_order(order_id: int, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT filename FROM order_files WHERE order_id=?", (order_id,))
    for row in c.fetchall():
        path = os.path.join(FILES_DIR, row[0])
        if os.path.exists(path): os.remove(path)
    c.execute("DELETE FROM order_files WHERE order_id=?", (order_id,))
    c.execute("DELETE FROM orders WHERE id=?", (order_id,))
    conn.commit()
    conn.close()
    return {"message": "Order deleted"}

# ── Files ──────────────────────────────────────────────────────────────────────

@app.get("/orders/{order_id}/files")
def get_files(order_id: int, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM order_files WHERE order_id=? ORDER BY uploaded_at DESC", (order_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

@app.post("/orders/{order_id}/files")
async def upload_file(
    order_id: int,
    file: UploadFile = File(...),
    username: str = Depends(verify_token)
):
    ext    = os.path.splitext(file.filename)[1]
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored = f"{order_id}_{ts}{ext}"
    path   = os.path.join(FILES_DIR, stored)
    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO order_files (order_id,filename,original_name,file_type,uploaded_by) VALUES (?,?,?,?,?)",
              (order_id, stored, file.filename, ext.lower(), username))
    conn.commit()
    conn.close()
    return {"message": "File uploaded", "filename": stored, "original_name": file.filename}

@app.delete("/files/{file_id}")
def delete_file(file_id: int, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM order_files WHERE id=?", (file_id,))
    row = c.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    path = os.path.join(FILES_DIR, row["filename"])
    if os.path.exists(path): os.remove(path)
    c.execute("DELETE FROM order_files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    return {"message": "File deleted"}

from fastapi.responses import FileResponse

@app.get("/files/{file_id}/download")
def download_file(file_id: int, username: str = Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM order_files WHERE id=?", (file_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    path = os.path.join(FILES_DIR, row["filename"])
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not on disk")
    return FileResponse(path, filename=row["original_name"])
