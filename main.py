from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from itsdangerous import URLSafeSerializer, BadSignature
import bcrypt, sqlite3, os

app    = FastAPI()
SECRET = "change-this-secret-key"
signer = URLSafeSerializer(SECRET)

# Always find files relative to THIS file, not where the server is run from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB       = os.path.join(BASE_DIR, "app.db")

# ── Database setup ───────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS activity (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            action     TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()

init_db()

# ── Helpers ──────────────────────────────────────────────
def read_html(filename: str) -> str:
    path = os.path.join(BASE_DIR, "static", filename)
    with open(path, "r") as f:
        return f.read()

def set_session(response, user_id: int, username: str):
    token = signer.dumps({"id": user_id, "username": username})
    response.set_cookie("session", token, httponly=True, max_age=60*60*24*7)

def get_session(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        return signer.loads(token)
    except BadSignature:
        return None

def log_activity(user_id: int, action: str):
    db = get_db()
    db.execute("INSERT INTO activity (user_id, action) VALUES (?, ?)", (user_id, action))
    db.commit()
    db.close()

# ── Pages ────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if get_session(request):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_html("index.html"))

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not get_session(request):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_html("dashboard.html"))

# ── API: Sign up ─────────────────────────────────────────
@app.post("/api/signup")
async def signup(request: Request):
    data     = await request.json()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return JSONResponse({"ok": False, "error": "All fields are required."})
    if len(password) < 6:
        return JSONResponse({"ok": False, "error": "Password must be at least 6 characters."})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        db  = get_db()
        cur = db.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed)
        )
        db.commit()
        user_id = cur.lastrowid
        db.close()
    except sqlite3.IntegrityError:
        return JSONResponse({"ok": False, "error": "Username or email already taken."})

    log_activity(user_id, "Account created")
    response = JSONResponse({"ok": True})
    set_session(response, user_id, username)
    return response

# ── API: Log in ──────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request):
    data     = await request.json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return JSONResponse({"ok": False, "error": "All fields are required."})

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return JSONResponse({"ok": False, "error": "Invalid email or password."})

    log_activity(user["id"], "Logged in")
    response = JSONResponse({"ok": True})
    set_session(response, user["id"], user["username"])
    return response

# ── API: Log out ─────────────────────────────────────────
@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("session")
    return response

# ── API: Dashboard data ──────────────────────────────────
@app.get("/api/me")
def me(request: Request):
    session = get_session(request)
    if not session:
        return JSONResponse({"ok": False}, status_code=401)

    db       = get_db()
    user     = db.execute("SELECT id, username, email, created_at FROM users WHERE id = ?", (session["id"],)).fetchone()
    activity = db.execute("SELECT action, created_at FROM activity WHERE user_id = ? ORDER BY created_at DESC LIMIT 10", (session["id"],)).fetchall()
    total    = db.execute("SELECT COUNT(*) as count FROM users").fetchone()
    db.close()

    return JSONResponse({
        "ok":         True,
        "user":       dict(user),
        "activity":   [dict(a) for a in activity],
        "totalUsers": total["count"]
    })
