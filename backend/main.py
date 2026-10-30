"""PaySovereignAI: dependency-free local demo server.

Run with Python 3.11+: python main.py. SQLite persists users, policies,
proposals, approvals, transactions, and audit events in paysov.db.
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import sqlite3, json, os, secrets, hashlib, hmac, time, re, threading

ROOT = Path(__file__).parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(ROOT)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "paysov.db"
SESSIONS = {}
LOCK = threading.RLock()
CATALOG = [
 {"id":"paper-01","name":"Recycled Paper Set","merchant":"Office Grove","merchant_id":"office-grove","category":"Office","price":18.50,"currency":"USD"},
 {"id":"desk-02","name":"Ergonomic Desk Lamp","merchant":"Office Grove","merchant_id":"office-grove","category":"Office","price":64.00,"currency":"USD"},
 {"id":"mug-03","name":"Ceramic Travel Mug","merchant":"Northstar Goods","merchant_id":"northstar-goods","category":"Home","price":24.00,"currency":"USD"},
 {"id":"head-04","name":"Studio Headphones","merchant":"Sound Loft","merchant_id":"sound-loft","category":"Electronics","price":149.00,"currency":"USD"},
]

def connect():
    c=sqlite3.connect(DB, timeout=15); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c

def init_db():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS policies(user_id TEXT PRIMARY KEY REFERENCES users(id),per_tx REAL NOT NULL,daily REAL NOT NULL,monthly REAL NOT NULL,currency TEXT NOT NULL,mode TEXT NOT NULL,merchants TEXT NOT NULL,approval_threshold REAL NOT NULL,approval_new INTEGER NOT NULL,version INTEGER NOT NULL DEFAULT 1,active INTEGER NOT NULL DEFAULT 1,updated TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),request_key TEXT NOT NULL,product_id TEXT NOT NULL,agent TEXT NOT NULL,merchant_id TEXT NOT NULL,merchant TEXT NOT NULL,product TEXT NOT NULL,amount REAL NOT NULL,currency TEXT NOT NULL,status TEXT NOT NULL,decision TEXT NOT NULL,reason TEXT NOT NULL,fingerprint TEXT NOT NULL,created REAL NOT NULL,UNIQUE(user_id,request_key));
        CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,proposal_id TEXT UNIQUE REFERENCES proposals(id),user_id TEXT REFERENCES users(id),status TEXT NOT NULL,decision_at REAL,fingerprint TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),proposal_id TEXT UNIQUE REFERENCES proposals(id),amount REAL NOT NULL,currency TEXT NOT NULL,payment_status TEXT NOT NULL,policy_status TEXT NOT NULL,paypal_order TEXT,paypal_capture TEXT,created REAL NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT REFERENCES users(id),entity_id TEXT,event TEXT,reason TEXT,metadata TEXT,created REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS proposal_user_time ON proposals(user_id,created);
        CREATE INDEX IF NOT EXISTS transaction_user_time ON transactions(user_id,created);
        CREATE INDEX IF NOT EXISTS audit_user_time ON audits(user_id,created);
        ''')

def pw_hash(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    return salt.hex()+"$"+hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000).hex()

def pw_ok(password, stored):
    try:
        salt, expected=stored.split("$"); actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),310000).hex()
        return hmac.compare_digest(actual,expected)
    except Exception: return False

def fingerprint(p):
    raw="|".join(str(p[k]) for k in ("product_id","merchant_id","amount","currency"))
    return hashlib.sha256(raw.encode()).hexdigest()

def evaluate(c,user_id,item,policy,exclude_proposal=None):
    amt=float(item["price"]); cur=item["currency"]
    if not policy or not policy["active"]: return "BLOCKED_POLICY","No active spending policy is configured."
    if cur != policy["currency"]: return "BLOCKED_POLICY","Purchase currency does not match the active policy."
    if amt>policy["per_tx"]: return "BLOCKED_BUDGET","The requested amount exceeds your per-transaction limit."
    if policy["mode"]=="allowlist" and item["merchant_id"] not in json.loads(policy["merchants"]): return "BLOCKED_MERCHANT","This merchant is not on your approved list."
    if policy["mode"]=="restriction" and item["merchant_id"] in json.loads(policy["merchants"]): return "BLOCKED_MERCHANT","This merchant is restricted by your policy."
    now=time.time(); day=now-86400; month=now-30*86400
    used=c.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? AND created>=? AND payment_status IN ('DEMO_RECORDED','COMPLETED','PAYMENT_PENDING')",(user_id,day)).fetchone()[0]
    if exclude_proposal: used+=c.execute("SELECT COALESCE(SUM(amount),0) FROM proposals WHERE user_id=? AND created>=? AND status IN ('READY_FOR_PAYMENT','PENDING_APPROVAL') AND id<>?",(user_id,day,exclude_proposal)).fetchone()[0]
    else: used+=c.execute("SELECT COALESCE(SUM(amount),0) FROM proposals WHERE user_id=? AND created>=? AND status IN ('READY_FOR_PAYMENT','PENDING_APPROVAL')",(user_id,day)).fetchone()[0]
    if used+amt>policy["daily"]: return "BLOCKED_BUDGET","This request would exceed your rolling 24-hour budget."
    usedm=c.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? AND created>=? AND payment_status IN ('DEMO_RECORDED','COMPLETED','PAYMENT_PENDING')",(user_id,month)).fetchone()[0]
    if exclude_proposal: usedm+=c.execute("SELECT COALESCE(SUM(amount),0) FROM proposals WHERE user_id=? AND created>=? AND status IN ('READY_FOR_PAYMENT','PENDING_APPROVAL') AND id<>?",(user_id,month,exclude_proposal)).fetchone()[0]
    else: usedm+=c.execute("SELECT COALESCE(SUM(amount),0) FROM proposals WHERE user_id=? AND created>=? AND status IN ('READY_FOR_PAYMENT','PENDING_APPROVAL')",(user_id,month)).fetchone()[0]
    if usedm+amt>policy["monthly"]: return "BLOCKED_BUDGET","This request would exceed your rolling 30-day budget."
    new=not c.execute("SELECT 1 FROM transactions WHERE user_id=? AND proposal_id IN (SELECT id FROM proposals WHERE merchant_id=?) LIMIT 1",(user_id,item["merchant_id"])).fetchone()
    if amt>=policy["approval_threshold"] or (new and policy["approval_new"]): return "PENDING_APPROVAL","Your policy requires your approval before this request can proceed."
    return "ALLOWED","The merchant and amount comply with your active policy."

def paypal_status(): return bool(os.getenv("PAYPAL_CLIENT_ID") and os.getenv("PAYPAL_CLIENT_SECRET"))

class Handler(BaseHTTPRequestHandler):
    server_version="PaySovereignAI/1.0"
    def log_message(self,*args): pass
    def send_json(self,obj,status=200):
        data=json.dumps(obj).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(data)
    def body(self):
        n=int(self.headers.get("Content-Length",0))
        if n>20000: raise ValueError("Request too large")
        return json.loads(self.rfile.read(n) or b"{}")
    def user(self):
        token=self.headers.get("Cookie","").split("paysov_session=",1)[-1].split(";",1)[0] if "paysov_session=" in self.headers.get("Cookie","") else ""
        return SESSIONS.get(token)
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/healthz": return self.send_json({"ok":True,"service":"paysov-api"})
        if path=="/api/me":
            u=self.user(); return self.send_json({"user":u,"paypal_configured":paypal_status()})
        if path.startswith("/api/"):
            u=self.user()
            if not u: return self.send_json({"error":"Sign in to continue."},401)
            with connect() as c:
                if path=="/api/policy":
                    p=c.execute("SELECT * FROM policies WHERE user_id=?",(u["id"],)).fetchone(); return self.send_json(dict(p) if p else {})
                if path=="/api/dashboard":
                    p=c.execute("SELECT * FROM policies WHERE user_id=?",(u["id"],)).fetchone(); tx=[dict(x) for x in c.execute("SELECT t.*,p.product,p.merchant,p.agent,p.reason,p.status proposal_status FROM transactions t JOIN proposals p ON p.id=t.proposal_id WHERE t.user_id=? ORDER BY t.created DESC LIMIT 100",(u["id"],))]
                    props=[dict(x) for x in c.execute("SELECT * FROM proposals WHERE user_id=? ORDER BY created DESC LIMIT 100",(u["id"],))]
                    approvals=[dict(x) for x in c.execute("SELECT a.*,p.product,p.merchant,p.amount,p.currency,p.agent,p.reason FROM approvals a JOIN proposals p ON p.id=a.proposal_id WHERE a.user_id=? AND a.status='PENDING' ORDER BY p.created",(u["id"],))]
                    return self.send_json({"policy":dict(p) if p else {},"transactions":tx,"proposals":props,"approvals":approvals,"catalog":CATALOG,"user":u,"paypal_configured":paypal_status()})
            return self.send_json({"error":"Not found"},404)
        try:
            data=(ROOT/"index.html").read_bytes(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        except OSError: self.send_error(404)
    def do_POST(self):
        path=urlparse(self.path).path
        try: data=self.body()
        except Exception: return self.send_json({"error":"Invalid request."},400)
        try:
            if path in ("/api/register","/api/login"):
                email=str(data.get("email","")).strip().lower(); password=str(data.get("password",""))
                if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email) or len(password)<10: return self.send_json({"error":"Enter a valid email and password with at least 10 characters."},400)
                with connect() as c:
                    if path.endswith("register"):
                        name=str(data.get("name","")).strip()
                        if len(name)<2 or not data.get("terms") or password!=str(data.get("confirm","")): return self.send_json({"error":"Enter your name, confirm your password, and accept the terms to continue."},400)
                        uid=secrets.token_urlsafe(16)
                        try: c.execute("INSERT INTO users(id,name,email,password_hash) VALUES(?,?,?,?)",(uid,name,email,pw_hash(password)))
                        except sqlite3.IntegrityError: return self.send_json({"error":"Unable to create account with those details."},409)
                        c.execute("INSERT INTO policies(user_id,per_tx,daily,monthly,currency,mode,merchants,approval_threshold,approval_new) VALUES(?,?,?,?,?,?,?,?,?)",(uid,50,100,1000,"USD","allowlist",json.dumps(["office-grove"]),35,1))
                        user={"id":uid,"name":name,"email":email}
                    else:
                        row=c.execute("SELECT id,name,email,password_hash FROM users WHERE email=?",(email,)).fetchone()
                        if not row or not pw_ok(password,row["password_hash"]): return self.send_json({"error":"Email or password is incorrect."},401)
                        user={"id":row["id"],"name":row["name"],"email":row["email"]}
                tok=secrets.token_urlsafe(32); SESSIONS[tok]=user; self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Set-Cookie",f"paysov_session={tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800" + ("; Secure" if os.getenv("HTTPS") else "")); self.end_headers(); self.wfile.write(json.dumps({"user":user}).encode()); return
            if path=="/api/logout":
                tok=self.headers.get("Cookie","").split("paysov_session=",1)[-1].split(";",1)[0]; SESSIONS.pop(tok,None)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Set-Cookie","paysov_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"); self.end_headers(); self.wfile.write(b'{"ok":true}'); return
            u=self.user()
            if not u: return self.send_json({"error":"Sign in to continue."},401)
            with LOCK, connect() as c:
                if path=="/api/policy":
                    per=float(data["per_tx"]); daily=float(data["daily"]); monthly=float(data["monthly"]); threshold=float(data["approval_threshold"])
                    cur=str(data.get("currency","USD")); mode=data.get("mode"); merchants=[str(x).lower().strip() for x in data.get("merchants",[]) if str(x).strip()]
                    if min(per,daily,monthly,threshold)<0 or not (per<=daily<=monthly) or cur not in ("USD","CAD","EUR","GBP","INR") or mode not in ("allowlist","restriction") or len(merchants)>100: return self.send_json({"error":"Policy values are invalid. Check limits, currency, and merchant mode."},400)
                    c.execute("INSERT INTO policies(user_id,per_tx,daily,monthly,currency,mode,merchants,approval_threshold,approval_new,version,updated) VALUES(?,?,?,?,?,?,?,?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET per_tx=excluded.per_tx,daily=excluded.daily,monthly=excluded.monthly,currency=excluded.currency,mode=excluded.mode,merchants=excluded.merchants,approval_threshold=excluded.approval_threshold,approval_new=excluded.approval_new,version=policies.version+1,updated=CURRENT_TIMESTAMP",(u["id"],per,daily,monthly,cur,mode,json.dumps(merchants),threshold,int(bool(data.get("approval_new"))))); return self.send_json({"ok":True})
                if path=="/api/propose":
                    key=str(data.get("request_key", ""))
                    if not key or len(key)>128: return self.send_json({"error":"A valid request identifier is required."},400)
                    existing=c.execute("SELECT * FROM proposals WHERE user_id=? AND request_key=?",(u["id"],key)).fetchone()
                    if existing: return self.send_json({"id":existing["id"],"decision":"BLOCKED_DUPLICATE","reason":"This request identifier has already been submitted.","status":existing["status"]},409)
                    item=next((x for x in CATALOG if x["id"]==data.get("product_id")),None)
                    if not item: return self.send_json({"error":"Select a product from the verified demo catalog."},400)
                    policy=c.execute("SELECT * FROM policies WHERE user_id=?",(u["id"],)).fetchone(); decision,reason=evaluate(c,u["id"],item,policy)
                    pid=secrets.token_urlsafe(14); status={"ALLOWED":"READY_FOR_PAYMENT","PENDING_APPROVAL":"PENDING_APPROVAL"}.get(decision,"BLOCKED"); fp=fingerprint(item)
                    c.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(pid,u["id"],key,item["id"],"PaySovereignAI demo agent",item["merchant_id"],item["merchant"],item["name"],item["price"],item["currency"],status,decision,reason,fp,time.time()))
                    c.execute("INSERT INTO audits(user_id,entity_id,event,reason,metadata,created) VALUES(?,?,?,?,?,?)",(u["id"],pid,"POLICY_EVALUATED",reason,json.dumps({"decision":decision}),time.time()))
                    if decision=="PENDING_APPROVAL": c.execute("INSERT INTO approvals VALUES(?,?,?,'PENDING',NULL,?)",(secrets.token_urlsafe(12),pid,u["id"],fp))
                    if status=="READY_FOR_PAYMENT": c.execute("INSERT INTO transactions VALUES(?,?,?, ?,?,'NOT_STARTED',?,NULL,NULL,?,?)",(secrets.token_urlsafe(12),u["id"],pid,item["price"],item["currency"],decision,time.time(),time.time()))
                    return self.send_json({"id":pid,"decision":decision,"reason":reason,"status":status,"demo":True},201)
                if path.startswith("/api/approval/"):
                    pid=path.rsplit("/",1)[-1]; action=data.get("action")
                    row=c.execute("SELECT p.*,a.fingerprint afp,a.status ast FROM proposals p JOIN approvals a ON a.proposal_id=p.id WHERE p.id=? AND p.user_id=?",(pid,u["id"])).fetchone()
                    if not row: return self.send_json({"error":"Approval request not found."},404)
                    if row["status"]!="PENDING_APPROVAL" or row["ast"]!="PENDING": return self.send_json({"error":"This approval is no longer pending."},409)
                    if not hmac.compare_digest(row["fingerprint"],row["afp"]): return self.send_json({"error":"Transaction details changed. A fresh approval is required."},409)
                    if action=="reject": c.execute("UPDATE approvals SET status='REJECTED',decision_at=? WHERE proposal_id=?",(time.time(),pid)); c.execute("UPDATE proposals SET status='CANCELLED' WHERE id=?",(pid,)); return self.send_json({"ok":True})
                    if action=="approve":
                        policy=c.execute("SELECT * FROM policies WHERE user_id=?",(u["id"],)).fetchone()
                        item=next((x for x in CATALOG if x["id"]==row["product_id"]),None)
                        if not item: return self.send_json({"error":"The verified product is no longer available."},409)
                        fresh,why=evaluate(c,u["id"],item,policy,exclude_proposal=pid)
                        # Approval only satisfies the user's review requirement; a changed or newly failing policy blocks advancement.
                        if fresh not in ("ALLOWED","PENDING_APPROVAL"): return self.send_json({"error":"Current policy no longer permits this request: "+why},409)
                        c.execute("UPDATE approvals SET status='APPROVED',decision_at=? WHERE proposal_id=?",(time.time(),pid)); c.execute("UPDATE proposals SET status='READY_FOR_PAYMENT' WHERE id=?",(pid,)); c.execute("INSERT INTO transactions VALUES(?,?,?, ?,?,'NOT_STARTED','ALLOWED',NULL,NULL,?,?)",(secrets.token_urlsafe(12),u["id"],pid,row["amount"],row["currency"],time.time(),time.time())); return self.send_json({"ok":True,"payment":"NOT_STARTED","message":"Approved. Payment has not been executed."})
                    return self.send_json({"error":"Choose approve or reject."},400)
                if path.startswith("/api/demo-pay/"):
                    tid=path.rsplit("/",1)[-1]; tx=c.execute("SELECT t.*,p.status ps FROM transactions t JOIN proposals p ON p.id=t.proposal_id WHERE t.id=? AND t.user_id=?",(tid,u["id"])).fetchone()
                    if not tx: return self.send_json({"error":"Transaction not found."},404)
                    if tx["payment_status"]!="NOT_STARTED": return self.send_json({"error":"This demo request was already processed."},409)
                    if tx["ps"]!="READY_FOR_PAYMENT": return self.send_json({"error":"Policy has not authorized this request."},409)
                    # Deliberately labeled simulation; no PayPal API is called and no payment occurs.
                    c.execute("UPDATE transactions SET payment_status='DEMO_RECORDED',updated=? WHERE id=?",(time.time(),tid)); c.execute("UPDATE proposals SET status='COMPLETED' WHERE id=?",(tx["proposal_id"],)); c.execute("INSERT INTO audits(user_id,entity_id,event,reason,metadata,created) VALUES(?,?,?,?,?,?)",(u["id"],tid,"DEMO_ONLY", "Sample workflow recorded; no payment was made.","{}",time.time())); return self.send_json({"ok":True,"payment_status":"DEMO_RECORDED","message":"Sample activity recorded. No payment was made."})
            return self.send_json({"error":"Not found."},404)
        except (ValueError,KeyError,TypeError): return self.send_json({"error":"Please check the submitted values."},400)
        except Exception: return self.send_json({"error":"The request could not be completed."},500)

if __name__=="__main__":
    init_db(); port=int(os.getenv("PORT","8000")); host=os.getenv("HOST","127.0.0.1"); print(f"PaySovereignAI API listening on {host}:{port}"); ThreadingHTTPServer((host,port),Handler).serve_forever()
