"""
SMS - Server Management System
Smart AI MFA + RBAC | Flask + SQLite | No Firebase
"""
from flask import Flask, request, jsonify, render_template, make_response
import pickle, pandas as pd, sqlite3, hashlib, jwt, time, random, string
import datetime, smtplib, os, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# ── CONFIG ─────────────────────────────────────────────────────────────────
EMAIL_SENDER        = "smart7mfa@gmail.com"
EMAIL_PASSWORD      = "qbfq ujgg pnpo ikrc"
JWT_SECRET          = "sms-rbac-secret-key-min32bytes-ok"
JWT_EXPIRY_HRS      = 8
SUPER_ADMIN_EMAIL   = "sanjay22522g@gmail.com"
SUPER_ADMIN_PASSWORD= "rbac@2006"
SUPER_ADMIN_NAME    = "Super Admin"
DB_PATH             = "/tmp/sms.db" if os.environ.get("RENDER") else "sms.db"

# ── SAFE MODEL LOAD ────────────────────────────────────────────────────────
model = None
try:
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)
    print("✅ model.pkl loaded successfully")
except FileNotFoundError:
    print("⚠️  model.pkl not found — heuristic fallback active")
except Exception as e:
    print(f"⚠️  model.pkl load error: {e} — heuristic fallback active")

# ── DATABASE ───────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name          TEXT DEFAULT '',
                role          TEXT DEFAULT 'user',
                status        TEXT DEFAULT 'active',
                created_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                email      TEXT,
                action     TEXT,
                risk_label TEXT DEFAULT 'low',
                status     TEXT,
                device     TEXT DEFAULT '',
                location   TEXT DEFAULT '',
                timestamp  TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_lu ON logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_lt ON logs(timestamp);
        """)

def ensure_super_admin():
    with get_db() as c:
        if not c.execute("SELECT id FROM users WHERE email=?", (SUPER_ADMIN_EMAIL,)).fetchone():
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            c.execute("INSERT INTO users (email,password_hash,name,role,created_at) VALUES (?,?,?,?,?)",
                      (SUPER_ADMIN_EMAIL, hash_pw(SUPER_ADMIN_PASSWORD), SUPER_ADMIN_NAME, "super_admin", ts))
            print(f"[INIT] Super Admin created: {SUPER_ADMIN_EMAIL}")

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

def db_user_email(email):
    with get_db() as c:
        r = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return dict(r) if r else None

def db_user_id(uid):
    with get_db() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(r) if r else None

def db_log(user_id, email, action, risk_label, status, device="", location=""):
    # Store as ISO 8601 with Z so JS correctly converts UTC → local time
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as c:
        c.execute(
            "INSERT INTO logs (user_id,email,action,risk_label,status,device,location,timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (user_id, email, action, risk_label, status, device, location, ts)
        )

init_db()
ensure_super_admin()

# ── OTP STORE ──────────────────────────────────────────────────────────────
_otp = {}  # { user_id: {otp, expires} }

# ── JWT ────────────────────────────────────────────────────────────────────
def make_jwt(user):
    return jwt.encode({
        "user_id": user["id"], "email": user["email"],
        "role": user["role"],  "name":  user["name"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRY_HRS)
    }, JWT_SECRET, algorithm="HS256")

def decode_jwt(token):
    try:    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"]), None
    except jwt.ExpiredSignatureError: return None, "Token expired"
    except jwt.InvalidTokenError:     return None, "Invalid token"

def get_token():
    a = request.headers.get("Authorization", "")
    return a[7:] if a.startswith("Bearer ") else request.cookies.get("token")

def need_role(*roles):
    t = get_token()
    if not t: return None, (jsonify({"error":"Unauthorized"}), 401)
    p, e = decode_jwt(t)
    if e:  return None, (jsonify({"error": e}), 401)
    if p.get("role") not in roles: return None, (jsonify({"error":"Forbidden"}), 403)
    return p, None

# ── EMAIL — VPN-compatible multi-method sender ─────────────────────────────
def send_email(receiver, otp):
    """
    VPN-compatible email sender.
    Tries multiple methods in order:
      1. smtp.gmail.com:587  STARTTLS  (standard)
      2. smtp.gmail.com:465  SSL       (works on many VPNs)
      3. smtp.gmail.com:443  STARTTLS  (port 443 is allowed by all VPNs)
      4. Direct Gmail IPs:465 SSL      (bypasses DNS failure entirely)
    """
    if not receiver or not otp:
        return False

    def make_msg():
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your SMS OTP Code"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = receiver
        text = (
            f"Your SMS OTP is: {otp}\n\n"
            f"Valid for 60 seconds. Do not share."
        )
        msg.attach(MIMEText(text, "plain"))
        return msg

    # Permissive SSL context — works through VPN inspection
    def make_ctx():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    # ── Method 1: STARTTLS port 587 ──────────────────────────────────────
    try:
        s = smtplib.SMTP("smtp.gmail.com", 587, timeout=12)
        s.ehlo(); s.starttls(context=make_ctx()); s.ehlo()
        s.login(EMAIL_SENDER, EMAIL_PASSWORD)
        s.send_message(make_msg()); s.quit()
        print(f"✅ OTP sent (587 STARTTLS) to {receiver}"); return True
    except Exception as e:
        print(f"⚠️  587 STARTTLS failed: {e}")

    # ── Method 2: SSL port 465 ───────────────────────────────────────────
    try:
        s = smtplib.SMTP_SSL("smtp.gmail.com", 465, context=make_ctx(), timeout=12)
        s.ehlo(); s.login(EMAIL_SENDER, EMAIL_PASSWORD)
        s.send_message(make_msg()); s.quit()
        print(f"✅ OTP sent (465 SSL) to {receiver}"); return True
    except Exception as e:
        print(f"⚠️  465 SSL failed: {e}")

    # ── Method 3: STARTTLS port 443 (VPN-safe — 443 always open) ────────
    try:
        s = smtplib.SMTP("smtp.gmail.com", 443, timeout=12)
        s.ehlo(); s.starttls(context=make_ctx()); s.ehlo()
        s.login(EMAIL_SENDER, EMAIL_PASSWORD)
        s.send_message(make_msg()); s.quit()
        print(f"✅ OTP sent (443 STARTTLS) to {receiver}"); return True
    except Exception as e:
        print(f"⚠️  443 STARTTLS failed: {e}")

    # ── Method 4: Direct Gmail SMTP IPs (bypasses DNS failure) ──────────
    # These are Google's real SMTP server IPs — updated 2025
    GMAIL_IPS = [
        "142.250.152.108",
        "142.250.4.108",
        "74.125.130.108",
        "74.125.140.108",
        "64.233.184.108",
    ]
    for ip in GMAIL_IPS:
        try:
            s = smtplib.SMTP_SSL(ip, 465, context=make_ctx(), timeout=10)
            s.ehlo("smtp.gmail.com")
            s.login(EMAIL_SENDER, EMAIL_PASSWORD)
            s.send_message(make_msg()); s.quit()
            print(f"✅ OTP sent (direct IP {ip}) to {receiver}"); return True
        except Exception as e:
            print(f"⚠️  IP {ip} failed: {e}")

    # ── All methods failed ───────────────────────────────────────────────
    print(f"❌ All email methods failed for {receiver}")
    print(f"[DEV] OTP for {receiver}: {otp}")  # visible in terminal for testing
    return False

# ── RISK ENGINE (YOUR original encode logic) ───────────────────────────────
def safe_int(v, d=0):
    try:    return int(v)
    except: return d

def parse_time(t):
    try:    return int(str(t).split(":")[0])
    except: return 12

def parse_location(loc):
    """
    0 = India (safe home country)
    1 = Foreign / Unknown (risky — if we can't detect, treat as foreign)
    """
    if not loc or str(loc).strip() == "":
        return 1  # empty = unknown = risky
    l = str(loc).strip().lower()
    # Only treat as safe if explicitly India
    if l in ["india"]:
        return 0
    # Unknown, empty, or any foreign country = risky
    return 1

def parse_device(dev):
    if not dev: return 0
    return 1 if "mobile" in str(dev).strip().lower() else 0

def encode(data):
    df = pd.DataFrame([[
        parse_device(data.get("device")),
        parse_location(data.get("location")),
        safe_int(data.get("loginCount"), 1),
        parse_time(data.get("time")),
        safe_int(data.get("failedAttempts"), 0)
    ]], columns=["device","location","loginCount","hour","failedAttempts"])
    print("MODEL INPUT:", df.values.tolist())
    return df

def run_predict(data):
    """Returns prediction int: 0=safe, 1=risky"""
    if model:
        try:
            p = int(model.predict(encode(data))[0])
            print(f"MODEL PREDICTION: {p}")
            return p
        except Exception as e:
            print(f"Model predict error: {e}")
    # Heuristic fallback
    hour   = parse_time(data.get("time"))
    failed = safe_int(data.get("failedAttempts"), 0)
    loc    = parse_location(data.get("location"))
    risky  = (hour < 6 or hour > 22 or failed >= 3 or loc == 1)
    p = 1 if risky else 0
    print(f"HEURISTIC PREDICTION: {p}")
    return p

# ══════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════════════════════════════
@app.route("/")         
def r_login():    return render_template("index.html")
@app.route("/signup")   
def r_signup():   return render_template("signup.html")
@app.route("/otp")      
def r_otp():      return render_template("otp.html")
@app.route("/home")     
def r_home():     return render_template("home.html")
@app.route("/super-admin") 
def r_sa():       return render_template("super_admin.html")
@app.route("/admin")    
def r_admin():    return render_template("admin.html")
@app.route("/user")     
def r_user():     return render_template("user.html")

# ══════════════════════════════════════════════════════════════════════════
#  YOUR ORIGINAL /send-otp and /predict (unchanged)
# ══════════════════════════════════════════════════════════════════════════
@app.route("/send-otp", methods=["POST"])
def send_otp_route():
    d = request.json or {}
    ok = send_email(d.get("email"), d.get("otp"))
    return jsonify({"status": "sent" if ok else "failed"})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json or {}
    print("RECEIVED:", data)
    pred = run_predict(data)
    print("PREDICTION:", pred, "(0=safe, 1=risky)")
    return jsonify({"prediction": pred})

# ══════════════════════════════════════════════════════════════════════════
#  AUTH API
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/signup", methods=["POST"])
def api_signup():
    d = request.get_json() or {}
    email = d.get("email","").strip().lower()
    pw    = d.get("password","")
    name  = d.get("name","").strip()
    if not email or not pw or not name:
        return jsonify({"error":"All fields required"}), 400
    if len(pw) < 6:
        return jsonify({"error":"Password must be at least 6 characters"}), 400
    if db_user_email(email):
        return jsonify({"error":"Email already registered"}), 409
    with get_db() as c:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        c.execute("INSERT INTO users (email,password_hash,name,role,created_at) VALUES (?,?,?,?,?)",
                  (email, hash_pw(pw), name, "user", ts))
    u = db_user_email(email)
    db_log(u["id"], email, "signup", "low", "success")
    return jsonify({"message":"Account created"}), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    d       = request.get_json() or {}
    email   = d.get("email","").strip().lower()
    pw      = d.get("password","")
    context = d.get("context", {})

    user = db_user_email(email)
    if not user or user["password_hash"] != hash_pw(pw):
        if user:
            db_log(user["id"], email, "login_failed", "low", "failed",
                   context.get("device",""), context.get("location",""))
        return jsonify({"error":"Invalid email or password"}), 401

    if user["status"] == "blocked":
        return jsonify({"error":"Account blocked. Contact Super Admin."}), 403

    # Use YOUR model to decide risk
    pred       = run_predict(context)
    risk_label = "high" if pred == 1 else "low"

    db_log(user["id"], email, "login_attempt", risk_label, "pending",
           context.get("device",""), context.get("location",""))

    if pred == 1:
        otp_code = "".join(random.choices(string.digits, k=6))
        _otp[user["id"]] = {"otp": otp_code, "expires": time.time() + 60}
        send_email(email, otp_code)
        return jsonify({"status":"otp_required","user_id":user["id"],"email":user["email"],"risk_label":risk_label})

    db_log(user["id"], email, "login_success", risk_label, "success",
           context.get("device",""), context.get("location",""))
    token = make_jwt(user)
    resp  = make_response(jsonify({"status":"success","token":token,"role":user["role"],"email":user["email"],"name":user["name"]}))
    resp.set_cookie("token", token, httponly=True, samesite="Strict", max_age=28800)
    return resp

@app.route("/api/verify-otp", methods=["POST"])
def api_verify_otp():
    d       = request.get_json() or {}
    uid     = d.get("user_id")
    otp_in  = (d.get("otp") or "").strip()
    if not uid or not otp_in:
        return jsonify({"error":"user_id and otp required"}), 400
    uid = int(uid)
    rec = _otp.get(uid)
    if not rec:                      return jsonify({"error":"OTP not found or expired"}), 400
    if time.time() > rec["expires"]: del _otp[uid]; return jsonify({"error":"OTP expired"}), 400
    if rec["otp"] != otp_in:
        u = db_user_id(uid)
        if u: db_log(uid, u["email"], "otp_failed", "high", "failed")
        return jsonify({"error":"Wrong OTP ❌"}), 401
    del _otp[uid]
    user = db_user_id(uid)
    db_log(uid, user["email"], "otp_verified", "high", "success")
    token = make_jwt(user)
    resp  = make_response(jsonify({"status":"success","token":token,"role":user["role"],"email":user["email"],"name":user["name"]}))
    resp.set_cookie("token", token, httponly=True, samesite="Strict", max_age=28800)
    return resp

@app.route("/api/resend-otp", methods=["POST"])
def api_resend_otp():
    d   = request.get_json() or {}
    uid = d.get("user_id")
    email = d.get("email","")
    if not uid: return jsonify({"error":"user_id required"}), 400
    otp_code = "".join(random.choices(string.digits, k=6))
    _otp[int(uid)] = {"otp": otp_code, "expires": time.time() + 60}
    send_email(email, otp_code)
    return jsonify({"status":"sent"})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"status":"logged out"}))
    resp.delete_cookie("token")
    return resp

# ══════════════════════════════════════════════════════════════════════════
#  SUPER ADMIN API
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/sa/stats")
def sa_stats():
    p, e = need_role("super_admin"); 
    if e: return e
    with get_db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users").fetchall()]
        logs  = [dict(r) for r in c.execute("SELECT * FROM logs").fetchall()]
    return jsonify({
        "total_users":   len(users),
        "active_users":  sum(1 for u in users if u["status"]=="active"),
        "blocked_users": sum(1 for u in users if u["status"]=="blocked"),
        "admin_count":   sum(1 for u in users if u["role"]=="admin"),
        "user_count":    sum(1 for u in users if u["role"]=="user"),
        "success_logins":sum(1 for l in logs  if l["status"]=="success"),
        "failed_logins": sum(1 for l in logs  if l["status"]=="failed"),
        "high_risk":     sum(1 for l in logs  if l["risk_label"]=="high"),
        "total_events":  len(logs)
    })

@app.route("/api/sa/users")
def sa_users():
    p, e = need_role("super_admin")
    if e: return e
    with get_db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()]
    for u in users: u.pop("password_hash", None)
    return jsonify({"users": users})

@app.route("/api/sa/users/<int:uid>/role", methods=["PUT"])
def sa_role(uid):
    p, e = need_role("super_admin")
    if e: return e
    role = (request.get_json() or {}).get("role")
    if role not in ("super_admin","admin","user"):
        return jsonify({"error":"Invalid role"}), 400
    u = db_user_id(uid)
    if u and u["email"] == SUPER_ADMIN_EMAIL:
        return jsonify({"error":"Cannot change Super Admin"}), 403
    with get_db() as c:
        c.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    return jsonify({"message":"Role updated"})

@app.route("/api/sa/users/<int:uid>/status", methods=["PUT"])
def sa_status(uid):
    p, e = need_role("super_admin")
    if e: return e
    status = (request.get_json() or {}).get("status")
    if status not in ("active","blocked"):
        return jsonify({"error":"Invalid status"}), 400
    u = db_user_id(uid)
    if u and u["email"] == SUPER_ADMIN_EMAIL:
        return jsonify({"error":"Cannot block Super Admin"}), 403
    with get_db() as c:
        c.execute("UPDATE users SET status=? WHERE id=?", (status, uid))
    return jsonify({"message":f"User {status}"})

@app.route("/api/sa/users/<int:uid>", methods=["DELETE"])
def sa_delete(uid):
    p, e = need_role("super_admin")
    if e: return e
    u = db_user_id(uid)
    if not u: return jsonify({"error":"Not found"}), 404
    if u["email"] == SUPER_ADMIN_EMAIL:
        return jsonify({"error":"Cannot delete Super Admin"}), 403
    with get_db() as c:
        c.execute("DELETE FROM logs  WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?",      (uid,))
    return jsonify({"message":"User deleted"})

@app.route("/api/sa/logs")
def sa_logs():
    p, e = need_role("super_admin")
    if e: return e
    limit = int(request.args.get("limit", 200))
    with get_db() as c:
        logs = [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]
    return jsonify({"logs": logs})

@app.route("/api/sa/security")
def sa_security():
    p, e = need_role("super_admin")
    if e: return e
    with get_db() as c:
        alerts = [dict(r) for r in c.execute("SELECT * FROM logs WHERE risk_label='high' ORDER BY timestamp DESC").fetchall()]
    return jsonify({"alerts": alerts})

@app.route("/api/sa/analytics")
def sa_analytics():
    p, e = need_role("super_admin")
    if e: return e
    trend = []
    with get_db() as c:
        for i in range(6, -1, -1):
            d   = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
            row = c.execute("""SELECT
                SUM(CASE WHEN status='success'   THEN 1 ELSE 0 END),
                SUM(CASE WHEN status='failed'    THEN 1 ELSE 0 END),
                SUM(CASE WHEN risk_label='high'  THEN 1 ELSE 0 END)
                FROM logs WHERE DATE(timestamp)=?""", (d,)).fetchone()
            trend.append({"date":d,"success":row[0] or 0,"failed":row[1] or 0,"high_risk":row[2] or 0})
        dist = {"low":0,"high":0}
        for r in c.execute("SELECT risk_label FROM logs").fetchall():
            if r[0]=="high": dist["high"]+=1
            else:            dist["low"]+=1
    return jsonify({"trend":trend,"risk_distribution":dist})

@app.route("/api/sa/analytics/rich")
def sa_analytics_rich():
    p, e = need_role("super_admin")
    if e: return e
    with get_db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users").fetchall()]
        logs  = [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY timestamp DESC").fetchall()]

    # Role distribution
    roles = {"super_admin":0,"admin":0,"user":0}
    for u in users:
        roles[u["role"]] = roles.get(u["role"],0)+1

    # Device breakdown
    devices = {}
    for l in logs:
        d = l.get("device","Unknown") or "Unknown"
        devices[d] = devices.get(d,0)+1

    # Location breakdown (top 10)
    locs = {}
    for l in logs:
        loc = l.get("location","Unknown") or "Unknown"
        locs[loc] = locs.get(loc,0)+1
    top_locs = sorted(locs.items(), key=lambda x: x[1], reverse=True)[:10]

    # Action breakdown
    actions = {}
    for l in logs:
        a = l.get("action","unknown") or "unknown"
        actions[a] = actions.get(a,0)+1

    # Hourly activity (0-23)
    hourly = [0]*24
    for l in logs:
        ts = l.get("timestamp","")
        try:
            h = datetime.datetime.fromisoformat(ts).hour
            hourly[h] += 1
        except: pass

    # Daily trend 30 days
    trend30 = []
    for i in range(29,-1,-1):
        d = (datetime.date.today()-datetime.timedelta(days=i)).isoformat()
        total = sum(1 for l in logs if l.get("timestamp","").startswith(d))
        trend30.append({"date":d,"count":total})

    # Status breakdown
    statuses = {"success":0,"failed":0,"pending":0}
    for l in logs:
        s = l.get("status","")
        statuses[s] = statuses.get(s,0)+1

    return jsonify({
        "role_distribution": roles,
        "device_breakdown":  devices,
        "top_locations":     top_locs,
        "action_breakdown":  actions,
        "hourly_activity":   hourly,
        "trend_30days":      trend30,
        "status_breakdown":  statuses,
        "total_users":       len(users),
        "total_logs":        len(logs)
    })

# ══════════════════════════════════════════════════════════════════════════
#  ADMIN API
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/admin/stats")
def admin_stats():
    p, e = need_role("super_admin","admin")
    if e: return e
    with get_db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users WHERE role!='super_admin'").fetchall()]
        logs  = [dict(r) for r in c.execute("SELECT * FROM logs").fetchall()]
    return jsonify({
        "total_users":   len(users),
        "active_users":  sum(1 for u in users if u["status"]=="active"),
        "blocked_users": sum(1 for u in users if u["status"]=="blocked"),
        "success_logins":sum(1 for l in logs  if l["status"]=="success"),
        "failed_logins": sum(1 for l in logs  if l["status"]=="failed"),
        "high_risk":     sum(1 for l in logs  if l["risk_label"]=="high"),
    })

@app.route("/api/admin/users")
def admin_users():
    p, e = need_role("super_admin","admin")
    if e: return e
    with get_db() as c:
        users = [dict(r) for r in c.execute("SELECT * FROM users WHERE role!='super_admin' ORDER BY created_at DESC").fetchall()]
    for u in users: u.pop("password_hash", None)
    return jsonify({"users": users})

@app.route("/api/admin/users/<int:uid>/status", methods=["PUT"])
def admin_status(uid):
    p, e = need_role("super_admin","admin")
    if e: return e
    status = (request.get_json() or {}).get("status")
    if status not in ("active","blocked"):
        return jsonify({"error":"Invalid status"}), 400
    u = db_user_id(uid)
    if u and u["role"]=="super_admin":
        return jsonify({"error":"Cannot modify Super Admin"}), 403
    with get_db() as c:
        c.execute("UPDATE users SET status=? WHERE id=?", (status, uid))
    return jsonify({"message":f"User {status}"})

@app.route("/api/admin/logs")
def admin_logs():
    p, e = need_role("super_admin","admin")
    if e: return e
    limit = int(request.args.get("limit",200))
    with get_db() as c:
        logs = [dict(r) for r in c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]
    return jsonify({"logs": logs})

@app.route("/api/admin/analytics")
def admin_analytics():
    p, e = need_role("super_admin","admin")
    if e: return e
    trend = []
    with get_db() as c:
        for i in range(6, -1, -1):
            d   = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
            row = c.execute("""SELECT
                SUM(CASE WHEN status='success'  THEN 1 ELSE 0 END),
                SUM(CASE WHEN status='failed'   THEN 1 ELSE 0 END),
                SUM(CASE WHEN risk_label='high' THEN 1 ELSE 0 END)
                FROM logs WHERE DATE(timestamp)=?""", (d,)).fetchone()
            trend.append({"date":d,"success":row[0] or 0,"failed":row[1] or 0,"high_risk":row[2] or 0})
        dist = {"low":0,"high":0}
        for r in c.execute("SELECT risk_label FROM logs").fetchall():
            if r[0]=="high": dist["high"]+=1
            else:            dist["low"]+=1
    return jsonify({"trend":trend,"risk_distribution":dist})

# ══════════════════════════════════════════════════════════════════════════
#  USER API
# ══════════════════════════════════════════════════════════════════════════
@app.route("/api/user/profile")
def user_profile():
    t = get_token()
    if not t: return jsonify({"error":"Unauthorized"}), 401
    p, e = decode_jwt(t)
    if e: return jsonify({"error":e}), 401
    u = db_user_id(p["user_id"])
    if not u: return jsonify({"error":"Not found"}), 404
    u.pop("password_hash", None)
    return jsonify({"profile": u})

@app.route("/api/user/profile", methods=["PUT"])
def update_profile():
    t = get_token()
    if not t: return jsonify({"error":"Unauthorized"}), 401
    p, e = decode_jwt(t)
    if e: return jsonify({"error":e}), 401
    name = ((request.get_json() or {}).get("name") or "").strip()
    if len(name) < 2: return jsonify({"error":"Name too short"}), 400
    with get_db() as c:
        c.execute("UPDATE users SET name=? WHERE id=?", (name, p["user_id"]))
    return jsonify({"message":"Profile updated"})

@app.route("/api/user/logs")
def user_logs():
    t = get_token()
    if not t: return jsonify({"error":"Unauthorized"}), 401
    p, e = decode_jwt(t)
    if e: return jsonify({"error":e}), 401
    with get_db() as c:
        logs = [dict(r) for r in c.execute(
            "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50", (p["user_id"],)
        ).fetchall()]
    return jsonify({"logs": logs})

# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\nSMS - Server Management System")
    print(f"Super Admin: {SUPER_ADMIN_EMAIL} / {SUPER_ADMIN_PASSWORD}")
    print(f"Visit: http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
