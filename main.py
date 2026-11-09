import os, re, zipfile, uuid, csv, io, hmac, hashlib, secrets, datetime as dt
from typing import Optional, List
import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Header
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Boolean, ForeignKey, DateTime, UniqueConstraint, func, inspect, text as sql_text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./site.db")
SECRET = os.getenv("SECRET_KEY", "change-me-in-production")
UP = "uploads"; os.makedirs(UP, exist_ok=True)
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
Session = sessionmaker(bind=engine)
Base = declarative_base()
pid = lambda: Column(Integer, ForeignKey("project.id"), index=True)

class Project(Base):
    __tablename__ = "project"; id = Column(Integer, primary_key=True); name = Column(String)
class User(Base):
    __tablename__ = "user"; id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True); pw = Column(String); nickname = Column(String)   # nickname = default for new projects
class ProjectMember(Base):   # many-to-many: a user can belong to many projects, with a role/nickname/doc access in each
    __tablename__ = "project_member"; id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id"), index=True); project_id = Column(Integer, ForeignKey("project.id"), index=True)
    role = Column(String, default="member"); nickname = Column(String); can_view_docs = Column(Boolean, default=False)
    can_view_totals = Column(Boolean, default=False)   # may see the Grand Total (admins always can)
    can_edit_entries = Column(Boolean, default=False)   # may edit/delete expenses, labor and stock (admins always can)
    __table_args__ = (UniqueConstraint("user_id", "project_id"),)
class Invite(Base):
    __tablename__ = "invite"; id = Column(Integer, primary_key=True); email = Column(String, index=True); project_id = pid()
class Expense(Base):
    __tablename__ = "expense"; id = Column(Integer, primary_key=True); project_id = pid()
    item = Column(String); amount = Column(Float); date = Column(Date); method = Column(String)
    paid_to = Column(String); proof = Column(String); by = Column(String)
class Labor(Base):
    __tablename__ = "labor"; id = Column(Integer, primary_key=True); project_id = pid()
    date = Column(Date); count = Column(Integer); notes = Column(String); by = Column(String); amount = Column(Float)
class Stock(Base):
    __tablename__ = "stock"; id = Column(Integer, primary_key=True); project_id = pid()
    material = Column(String); qty = Column(Float); unit = Column(String); date = Column(Date)
    supplier = Column(String); by = Column(String)
class Doc(Base):
    __tablename__ = "doc"; id = Column(Integer, primary_key=True); project_id = pid()
    title = Column(String); file = Column(String); by = Column(String); created = Column(DateTime, default=dt.datetime.utcnow)
Base.metadata.create_all(engine)
if "amount" not in [c["name"] for c in inspect(engine).get_columns("labor")]:   # add wages column to existing databases
    with engine.begin() as c: c.execute(sql_text("ALTER TABLE labor ADD COLUMN amount FLOAT"))

def migrate_memberships():
    """One-time upgrade: copy each user's old (project_id, role, can_docs, nickname) into project_member. Nothing is deleted."""
    if "project_id" not in [c["name"] for c in inspect(engine).get_columns("user")]: return   # fresh database
    with engine.begin() as c:
        if c.execute(sql_text("SELECT COUNT(*) FROM project_member")).scalar(): return   # already migrated
        old = c.execute(sql_text('SELECT id, project_id, role, can_docs, nickname FROM "user" WHERE project_id IS NOT NULL')).fetchall()
        for uid, pid_, role, docs, nick in old:
            c.execute(sql_text("INSERT INTO project_member (user_id, project_id, role, nickname, can_view_docs) VALUES (:u, :p, :r, :n, :d)"),
                      {"u": uid, "p": pid_, "r": role or "member", "n": nick or "", "d": bool(docs) or role == "admin"})
migrate_memberships()
if "can_view_totals" not in [c["name"] for c in inspect(engine).get_columns("project_member")]:   # add the new permission to existing databases
    with engine.begin() as c:
        c.execute(sql_text("ALTER TABLE project_member ADD COLUMN can_view_totals BOOLEAN DEFAULT " + ("0" if engine.dialect.name == "sqlite" else "FALSE")))
if "can_edit_entries" not in [c["name"] for c in inspect(engine).get_columns("project_member")]:   # add the edit permission to existing databases
    with engine.begin() as c:
        c.execute(sql_text("ALTER TABLE project_member ADD COLUMN can_edit_entries BOOLEAN DEFAULT " + ("0" if engine.dialect.name == "sqlite" else "FALSE")))

app = FastAPI(title="Nestify")
bearer = HTTPBearer(auto_error=False)

def get_db():
    db = Session()
    try: yield db
    finally: db.close()

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100_000).hex()
def check_pw(p, stored):
    return hmac.compare_digest(hash_pw(p, stored.split("$")[0]), stored)

class Ctx:
    """The signed-in user as seen inside ONE project (role, nickname and doc access are per project)."""
    def __init__(s, user, pm):
        s.user, s.pm = user, pm
        s.id, s.email = user.id, user.email
        s.project_id, s.role, s.nickname, s.can_docs = pm.project_id, pm.role, pm.nickname, bool(pm.can_view_docs)
        s.can_totals = pm.role == "admin" or bool(pm.can_view_totals)
        s.can_edit = pm.role == "admin" or bool(pm.can_edit_entries)

def auth_user(cred=Depends(bearer), db=Depends(get_db)):
    try:
        uid = jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])["uid"]
    except Exception:
        raise HTTPException(401, "Please log in again")
    u = db.get(User, uid)
    if not u: raise HTTPException(401, "Unknown user")
    return u

def me(u=Depends(auth_user), x_project_id: Optional[int] = Header(None), db=Depends(get_db)):
    q = db.query(ProjectMember).filter(ProjectMember.user_id == u.id)
    pm = q.filter(ProjectMember.project_id == x_project_id).first() if x_project_id else q.order_by(ProjectMember.id).first()
    if not pm: raise HTTPException(403, "You are not a member of this project")
    return Ctx(u, pm)

def editor(u=Depends(me)):   # admins, or members the admin granted "Can Edit"
    if not u.can_edit: raise HTTPException(403, "You don't have permission to edit or delete entries")
    return u

def admin(u=Depends(me)):
    if u.role != "admin": raise HTTPException(403, "Admin only")
    return u

def row(o): return {c.name: getattr(o, c.name) for c in o.__table__.columns}
def token(u): return jwt.encode({"uid": u.id, "exp": dt.datetime.utcnow() + dt.timedelta(days=30)}, SECRET, algorithm="HS256")
def profile(u): return {"id": u.id, "email": u.email, "nickname": u.nickname, "role": u.role, "can_docs": u.can_docs or u.role == "admin", "can_totals": u.can_totals, "can_edit": u.can_edit}

def save(f: Optional[UploadFile]):
    if not f or not f.filename: return None
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in {".jpg", ".jpeg", ".png", ".webp", ".pdf"}: raise HTTPException(400, "Only images or PDF allowed")
    name = uuid.uuid4().hex + ext
    with open(os.path.join(UP, name), "wb") as out: out.write(f.file.read())
    return name

def parse_date(s):
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try: return dt.datetime.strptime(s.strip(), fmt).date()
        except ValueError: pass
    raise ValueError(s)

# ---------- auth ----------
class Reg(BaseModel):
    email: str; password: str; nickname: str; project_name: str = ""
class Login(BaseModel):
    email: str; password: str

def uprofile(u): return {"id": u.id, "email": u.email, "nickname": u.nickname}

@app.post("/api/register")
def register(b: Reg, db=Depends(get_db)):
    email = b.email.strip().lower()
    if len(b.password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    if db.query(User).filter_by(email=email).first(): raise HTTPException(400, "Email already registered. Log in instead; an admin can add you to other projects directly")
    invites = db.query(Invite).filter_by(email=email).all()
    if not invites and not b.project_name.strip():
        raise HTTPException(400, "Enter a project name to start a new project, or ask the admin to invite your email")
    nick = b.nickname.strip() or email.split("@")[0]
    u = User(email=email, pw=hash_pw(b.password), nickname=nick); db.add(u); db.flush()
    for inv in invites:   # pending invites become memberships
        db.add(ProjectMember(user_id=u.id, project_id=inv.project_id, role="member", nickname=nick)); db.delete(inv)
    if b.project_name.strip():
        p = Project(name=b.project_name.strip()); db.add(p); db.flush()
        db.add(ProjectMember(user_id=u.id, project_id=p.id, role="admin", nickname=nick, can_view_docs=True))
    db.commit()
    return {"token": token(u), "user": uprofile(u)}

@app.post("/api/login")
def login(b: Login, db=Depends(get_db)):
    u = db.query(User).filter_by(email=b.email.strip().lower()).first()
    if not u or not check_pw(b.password, u.pw): raise HTTPException(400, "Wrong email or password")
    return {"token": token(u), "user": uprofile(u)}

@app.get("/api/projects")
def my_projects(u=Depends(auth_user), db=Depends(get_db)):
    rows = (db.query(ProjectMember, Project).join(Project, Project.id == ProjectMember.project_id)
            .filter(ProjectMember.user_id == u.id).order_by(ProjectMember.id).all())
    return [{"id": p.id, "name": p.name, "role": pm.role} for pm, p in rows]

class NewProject(BaseModel):
    name: str

@app.post("/api/projects")
def new_project(b: NewProject, u=Depends(auth_user), db=Depends(get_db)):
    if not b.name.strip(): raise HTTPException(400, "Project name required")
    p = Project(name=b.name.strip()); db.add(p); db.flush()
    db.add(ProjectMember(user_id=u.id, project_id=p.id, role="admin", nickname=u.nickname, can_view_docs=True)); db.commit()
    return {"id": p.id, "name": p.name, "role": "admin"}

class Nick(BaseModel):
    nickname: str

@app.get("/api/me")
def get_me(u=Depends(me), db=Depends(get_db)):
    return {**profile(u), "project": db.get(Project, u.project_id).name, "project_id": u.project_id}

@app.patch("/api/me")
def set_nick(b: Nick, u=Depends(me), db=Depends(get_db)):   # nickname applies to the active project only
    if not b.nickname.strip(): raise HTTPException(400, "Nickname required")
    u.pm.nickname = u.nickname = b.nickname.strip(); db.commit(); return profile(u)

# ---------- expenses ----------
@app.get("/api/expenses")
def list_expenses(u=Depends(me), db=Depends(get_db)):
    return [row(x) for x in db.query(Expense).filter_by(project_id=u.project_id).order_by(Expense.date.desc(), Expense.id.desc())]

@app.post("/api/expenses")
def add_expense(item: str = Form(...), amount: float = Form(...), date: Optional[dt.date] = Form(None),
                method: str = Form("Cash"), paid_to: str = Form(""), proof: Optional[UploadFile] = File(None),
                u=Depends(me), db=Depends(get_db)):
    e = Expense(project_id=u.project_id, item=item, amount=amount, date=date or dt.date.today(), method=method,
                paid_to=paid_to, proof=save(proof), by=u.nickname)
    db.add(e); db.commit(); return row(e)

def norm(s): return re.sub(r"\s+", " ", (s or "").strip().lower())
def exp_key(d, amt, item): return (d, round(float(amt or 0), 2), norm(item))
def lab_key(d, cnt, amt, note): return (d, int(cnt or 0), round(float(amt or 0), 2), norm(note))

def existing_keys(db, pid):
    """Keys of records already in this project, used to skip duplicates on import."""
    ex = {exp_key(d, a, i) for d, a, i in db.query(Expense.date, Expense.amount, Expense.item).filter(Expense.project_id == pid)}
    lb = {lab_key(d, c, a, n) for d, c, a, n in db.query(Labor.date, Labor.count, Labor.amount, Labor.notes).filter(Labor.project_id == pid)}
    return ex, lb

@app.post("/api/expenses/import")
def import_expenses(file: UploadFile = File(...), u=Depends(me), db=Depends(get_db)):
    reader = csv.DictReader(io.StringIO(file.file.read().decode("utf-8-sig", errors="replace")))
    ex, _ = existing_keys(db, u.project_id)
    n, dup, bad = 0, 0, []
    for i, r in enumerate(reader, start=2):
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        try:
            d, a, item = parse_date(r["date"]), float(r["amount"].replace(",", "")), r["item"]
            if exp_key(d, a, item) in ex: dup += 1; continue
            db.add(Expense(project_id=u.project_id, item=item, amount=a, date=d, method=r.get("method") or "Cash",
                           paid_to=r.get("paid_to", ""), by=u.nickname))
            n += 1
        except Exception:
            bad.append(i)
    db.commit(); return {"imported": n, "duplicates": dup, "skipped_rows": bad}

# ---------- WhatsApp chat parser ----------
WA_LINE = re.compile(r"^[\u200e\u200f]*\[?(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4}),?\s+\d{1,2}[:.]\d{2}(?:[:.]\d{2})?\s*(?:[APap]\.?[Mm]\.?)?\]?\s*(?:-\s*)?(.*)$")
AMT_PRE = re.compile(r"(?:₹|\brs\.?|\binr)\s*(\d[\d,]*(?:\.\d+)?)", re.I)
AMT_POST = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*(?:/-|₹|\brs\b\.?|\binr\b)", re.I)
NUM = re.compile(r"(?<![\w.,])\d[\d,]*(?:\.\d+)?(?!\w)")
WA_METHODS = [(r"\b(upi|gpay|google ?pay|phonepe|paytm)\b", "UPI"), (r"\b(cheque|check)\b", "Cheque"),
              (r"\b(neft|imps|rtgs|bank|transfer)\b", "Bank Transfer"), (r"\bcash\b", "Cash")]
LABOR_KW = re.compile(r"\b(?:labou?rers?|labou?rs?|coolies|coolie|masons?|wages?|hajiri|majdoors?)\b", re.I)
COUNT_RE = re.compile(r"(\d+)\s*(?:labou?rers?|labou?rs?|coolies|coolie|masons?|workers?|helpers?|people|persons?)\b", re.I)
ATTACH_RE = re.compile(r"([\w\-.()]+\.(?:jpe?g|png|webp|pdf))\s*\(file attached\)|<attached:\s*([^>]+?)>", re.I)
PROOF_EXT = {".jpg", ".jpeg", ".png", ".webp", ".pdf"}
STAGED = re.compile(r"^[0-9a-f]{32}\.(?:jpg|jpeg|png|webp|pdf)$")

def wa_date(m, order):
    d, mo = (m[0], m[1]) if order == "dmy" else (m[1], m[0])
    y = m[2] + 2000 if m[2] < 100 else m[2]
    try: return dt.date(y, mo, d)
    except ValueError: return None

def wa_parts(body):
    """Split '500 binding wire + 20000 labour' into separate items (only if every piece has a number)."""
    parts = [p.strip() for p in re.split(r"\s*\+\s*", body)]
    return parts if len(parts) > 1 and all(re.search(r"\d", p) for p in parts) else [body]

def wa_entry(p, sender, date):
    kind = "labor" if LABOR_KW.search(p) else "expense"
    q, count = p, 0
    if kind == "labor":   # '5 labour' = headcount, so keep it out of the wage amount search
        c = COUNT_RE.search(p)
        if c and int(c.group(1)) <= 200:
            count = int(c.group(1)); q = p[:c.start()] + " " * (c.end() - c.start()) + p[c.end():]
    hit = AMT_PRE.search(q) or AMT_POST.search(q)
    if not hit and "?" in p: return None
    amt, span, guess = None, None, False
    if hit:
        amt, span = float(hit.group(1).replace(",", "")), hit.span()
    else:   # no currency marker: largest plain number, flagged for review
        nums = [(float(x.group().replace(",", "")), x.span()) for x in NUM.finditer(q)
                if len(re.sub(r"\D", "", x.group())) <= 7]
        if nums: amt, span = max(nums); guess = True
    if amt is not None and amt <= 0: amt, span = None, None
    if (kind == "expense" and not amt) or (kind == "labor" and not amt and not count): return None
    item = re.sub(r"\s+", " ", (p[:span[0]] + " " + p[span[1]:]) if span else p).strip(" -:,;.") or "WhatsApp entry"
    to = re.search(r"\bto\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)?)", p)
    method = next((name for pat, name in WA_METHODS if re.search(pat, p, re.I)), "Cash")
    return {"kind": kind, "date": date.isoformat(), "item": item, "amount": amt, "count": count, "method": method,
            "paid_to": to.group(1) if to else sender, "sender": sender, "guess": guess, "attachment": None}

def parse_whatsapp(text, order="auto"):
    msgs = []  # [a, b, year, sender, body]; None = system line
    for line in text.splitlines():
        m = WA_LINE.match(line)
        if m:
            a, b, y, rest = m.groups()
            if ": " in rest:
                sender, body = rest.split(": ", 1)
                msgs.append([int(a), int(b), int(y), sender.strip(), body.strip()])
            else:
                msgs.append(None)
        elif msgs and msgs[-1]:
            msgs[-1][4] += " " + line.strip()   # continuation of a multi-line message
    msgs = [m for m in msgs if m]
    if order not in ("dmy", "mdy"):
        order = "mdy" if any(m[1] > 12 for m in msgs) and not any(m[0] > 12 for m in msgs) else "dmy"
    out, skipped = [], 0
    for m in msgs:
        body, date = m[4], wa_date(m, order)
        if date is None or re.search(r"media omitted|message was deleted|^null$", body, re.I):
            skipped += 1; continue
        atts = [(a or b).strip() for a, b in ATTACH_RE.findall(body)]
        body = re.sub(r"\s+", " ", ATTACH_RE.sub(" ", body)).strip()
        if not body:   # photo-only message: attach to this sender's previous entry the same day
            if atts and out and out[-1]["sender"] == m[3] and out[-1]["date"] == date.isoformat() and not out[-1]["attachment"]:
                out[-1]["attachment"] = atts[0]
            else: skipped += 1
            continue
        new = [e for e in (wa_entry(p, m[3], date) for p in wa_parts(body)) if e]
        if not new: skipped += 1; continue
        if atts: new[0]["attachment"] = atts[0]
        out.extend(new)
    return {"entries": out, "order": order, "skipped": skipped}

def read_chat_upload(f):
    """Return (chat text, ZipFile or None) from a .txt or a WhatsApp .zip export."""
    raw, z = f.file.read(), None
    if (f.filename or "").lower().endswith(".zip") or raw[:2] == b"PK":
        try: z = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile: raise HTTPException(400, "Could not read that zip file")
        txts = [n for n in z.namelist() if n.lower().endswith(".txt") and not n.startswith("__MACOSX")]
        if not txts: raise HTTPException(400, "No .txt chat file found inside the zip")
        base = lambda n: os.path.basename(n)
        pick = next((n for n in txts if base(n).lower() == "_chat.txt" or base(n).startswith("WhatsApp Chat")), txts[0])
        if z.getinfo(pick).file_size > 25_000_000: raise HTTPException(400, "Chat file is too large")
        raw = z.read(pick)
    return raw.decode("utf-8-sig", errors="replace"), z

@app.post("/api/expenses/whatsapp/preview")
def wa_preview(file: UploadFile = File(...), order: str = Form("auto"), u=Depends(me), db=Depends(get_db)):
    text, z = read_chat_upload(file)
    res = parse_whatsapp(text, order)
    ex, lb = existing_keys(db, u.project_id)
    media = {os.path.basename(n).lower(): n for n in z.namelist()} if z else {}
    folder = os.path.join(UP, "staged", str(u.project_id))
    for e in res["entries"]:
        label = e.pop("attachment", None)
        d = dt.date.fromisoformat(e["date"])
        e["dup_expense"] = bool(e["amount"]) and exp_key(d, e["amount"], e["item"]) in ex
        e["dup_labor"] = lab_key(d, e["count"], e["amount"], e["item"]) in lb
        e["proof"], e["proof_label"] = None, label
        key = (label or "").lower()
        ext = os.path.splitext(key)[1]
        if key in media and ext in PROOF_EXT and z.getinfo(media[key]).file_size <= 10_000_000:
            os.makedirs(folder, exist_ok=True)
            name = uuid.uuid4().hex + ext   # staged until the user confirms the import
            with open(os.path.join(folder, name), "wb") as out: out.write(z.read(media[key]))
            e["proof"] = name
    return res

@app.get("/api/staged/{name}")
def staged_file(name: str, u=Depends(me)):
    p = os.path.join(UP, "staged", str(u.project_id), name)
    if not STAGED.match(name) or not os.path.exists(p): raise HTTPException(404, "Not found")
    return FileResponse(p)

class BulkRow(BaseModel):
    kind: str = "expense"; item: str; amount: Optional[float] = None; date: dt.date
    method: str = "Cash"; paid_to: str = ""; count: int = 0; proof: Optional[str] = None

def commit_staged(name, project_id):
    if not name or not STAGED.match(name): return None
    src = os.path.join(UP, "staged", str(project_id), name)
    if not os.path.exists(src): return None
    os.replace(src, os.path.join(UP, name)); return name

@app.post("/api/expenses/bulk")
def bulk_expenses(rows: List[BulkRow], u=Depends(me), db=Depends(get_db)):
    ex, lb = existing_keys(db, u.project_id)   # duplicates = same date + amount + item already in this project
    ne = nl = nd = 0
    for r in rows:
        if r.kind == "labor":
            if not r.count and not r.amount: continue
            if lab_key(r.date, r.count, r.amount, r.item) in lb: nd += 1; continue
            db.add(Labor(project_id=u.project_id, date=r.date, count=r.count, notes=r.item, amount=r.amount, by=u.nickname)); nl += 1
        else:
            if not r.amount or r.amount <= 0: continue
            if exp_key(r.date, r.amount, r.item) in ex: nd += 1; continue
            db.add(Expense(project_id=u.project_id, item=r.item, amount=r.amount, date=r.date, method=r.method,
                           paid_to=r.paid_to, proof=commit_staged(r.proof, u.project_id), by=u.nickname)); ne += 1
    db.commit(); return {"saved": ne + nl, "expenses": ne, "labor": nl, "skipped": nd}

class ExpenseEdit(BaseModel):
    item: str; amount: float; date: dt.date; method: str; paid_to: str = ""

@app.put("/api/expenses/{eid}")
def edit_expense(eid: int, b: ExpenseEdit, u=Depends(editor), db=Depends(get_db)):
    e = db.get(Expense, eid)
    if not e or e.project_id != u.project_id: raise HTTPException(404, "Not found")
    e.item, e.amount, e.date, e.method, e.paid_to = b.item.strip(), b.amount, b.date, b.method, b.paid_to.strip()
    db.commit(); return row(e)   # 'by' keeps the original submitter for the audit trail

@app.delete("/api/expenses/{eid}")
def delete_expense(eid: int, u=Depends(editor), db=Depends(get_db)):
    e = db.get(Expense, eid)
    if not e or e.project_id != u.project_id: raise HTTPException(404, "Not found")
    if e.proof:
        try: os.remove(os.path.join(UP, e.proof))
        except OSError: pass
    db.delete(e); db.commit(); return {"ok": True}

@app.get("/api/expenses/{eid}/proof")
def proof(eid: int, u=Depends(me), db=Depends(get_db)):
    e = db.get(Expense, eid)
    if not e or e.project_id != u.project_id or not e.proof: raise HTTPException(404, "No proof")
    return FileResponse(os.path.join(UP, e.proof))

# ---------- labor & stock ----------
class LaborIn(BaseModel):
    date: dt.date; count: int; notes: str = ""; amount: Optional[float] = None
class StockIn(BaseModel):
    material: str; qty: float; unit: str; date: dt.date; supplier: str = ""

@app.get("/api/labor")
def list_labor(u=Depends(me), db=Depends(get_db)):
    return [row(x) for x in db.query(Labor).filter_by(project_id=u.project_id).order_by(Labor.date.desc(), Labor.id.desc())]

@app.post("/api/labor")
def add_labor(b: LaborIn, u=Depends(me), db=Depends(get_db)):
    x = Labor(project_id=u.project_id, by=u.nickname, **b.dict()); db.add(x); db.commit(); return row(x)

@app.get("/api/stock")
def list_stock(u=Depends(me), db=Depends(get_db)):
    return [row(x) for x in db.query(Stock).filter_by(project_id=u.project_id).order_by(Stock.date.desc(), Stock.id.desc())]

@app.post("/api/stock")
def add_stock(b: StockIn, u=Depends(me), db=Depends(get_db)):
    x = Stock(project_id=u.project_id, by=u.nickname, **b.dict()); db.add(x); db.commit(); return row(x)

@app.put("/api/stock/{sid}")
def edit_stock(sid: int, b: StockIn, u=Depends(editor), db=Depends(get_db)):
    x = db.get(Stock, sid)
    if not x or x.project_id != u.project_id: raise HTTPException(404, "Not found")
    x.material, x.qty, x.unit, x.date, x.supplier = b.material.strip(), b.qty, b.unit.strip(), b.date, b.supplier.strip()
    db.commit(); return row(x)

@app.delete("/api/stock/{sid}")
def delete_stock(sid: int, u=Depends(editor), db=Depends(get_db)):
    x = db.get(Stock, sid)
    if not x or x.project_id != u.project_id: raise HTTPException(404, "Not found")
    db.delete(x); db.commit(); return {"ok": True}

class LaborEdit(BaseModel):
    date: dt.date; count: int; notes: str = ""; amount: Optional[float] = None

@app.put("/api/labor/{lid}")
def edit_labor(lid: int, b: LaborEdit, u=Depends(editor), db=Depends(get_db)):
    x = db.get(Labor, lid)
    if not x or x.project_id != u.project_id: raise HTTPException(404, "Not found")
    x.date, x.count, x.notes, x.amount = b.date, b.count, b.notes.strip(), b.amount
    db.commit(); return row(x)

@app.delete("/api/labor/{lid}")
def delete_labor(lid: int, u=Depends(editor), db=Depends(get_db)):
    x = db.get(Labor, lid)
    if not x or x.project_id != u.project_id: raise HTTPException(404, "Not found")
    db.delete(x); db.commit(); return {"ok": True}

def totals_ok(u=Depends(me)):
    if not u.can_totals: raise HTTPException(403, "Restricted (Admin only)")
    return u

@app.get("/api/totals")   # the only place aggregated spend is computed; refused for members without permission
def totals(u=Depends(totals_ok), db=Depends(get_db)):
    e = db.query(func.coalesce(func.sum(Expense.amount), 0)).filter(Expense.project_id == u.project_id).scalar()
    l = db.query(func.coalesce(func.sum(Labor.amount), 0)).filter(Labor.project_id == u.project_id).scalar()
    return {"expenses": float(e), "labor": float(l), "grand": float(e) + float(l)}

# ---------- team ----------
class Inv(BaseModel):
    email: str
class Allow(BaseModel):
    allow: bool

@app.get("/api/members")
def members(u=Depends(admin), db=Depends(get_db)):
    rows = (db.query(ProjectMember, User).join(User, User.id == ProjectMember.user_id)
            .filter(ProjectMember.project_id == u.project_id).order_by(ProjectMember.id).all())
    iv = db.query(Invite).filter_by(project_id=u.project_id).all()
    return {"members": [{"id": x.id, "email": x.email, "nickname": pm.nickname, "role": pm.role,
                         "can_docs": bool(pm.can_view_docs) or pm.role == "admin",
                         "can_totals": bool(pm.can_view_totals) or pm.role == "admin",
                         "can_edit": bool(pm.can_edit_entries) or pm.role == "admin"} for pm, x in rows],
            "invites": [i.email for i in iv]}

@app.post("/api/invite")
def invite(b: Inv, u=Depends(admin), db=Depends(get_db)):
    email = b.email.strip().lower()
    ex = db.query(User).filter_by(email=email).first()
    if ex:   # already registered: link the existing account to this project, no re-registration needed
        if db.query(ProjectMember).filter_by(user_id=ex.id, project_id=u.project_id).first():
            raise HTTPException(400, "Already a member of this project")
        db.add(ProjectMember(user_id=ex.id, project_id=u.project_id, role="member", nickname=ex.nickname)); db.commit()
        return {"ok": True, "added": True}
    if not db.query(Invite).filter_by(email=email, project_id=u.project_id).first():
        db.add(Invite(email=email, project_id=u.project_id))
    db.commit(); return {"ok": True, "added": False}

@app.patch("/api/members/{mid}/docs")
def doc_access(mid: int, b: Allow, u=Depends(admin), db=Depends(get_db)):
    m = db.query(ProjectMember).filter_by(user_id=mid, project_id=u.project_id).first()
    if not m: raise HTTPException(404, "Not found")
    m.can_view_docs = b.allow; db.commit(); return {"ok": True, "can_docs": b.allow}

class Perms(BaseModel):
    can_view_docs: Optional[bool] = None; can_view_totals: Optional[bool] = None; can_edit_entries: Optional[bool] = None

@app.patch("/api/team/{member_id}/permissions")   # member_id = the member's user id
def set_permissions(member_id: int, b: Perms, u=Depends(admin), db=Depends(get_db)):
    m = db.query(ProjectMember).filter_by(user_id=member_id, project_id=u.project_id).first()
    if not m: raise HTTPException(404, "Not found")
    if m.role == "admin": raise HTTPException(400, "Admins always have full access")
    if b.can_view_docs is not None: m.can_view_docs = b.can_view_docs
    if b.can_view_totals is not None: m.can_view_totals = b.can_view_totals
    if b.can_edit_entries is not None: m.can_edit_entries = b.can_edit_entries
    db.commit(); return {"ok": True, "can_docs": bool(m.can_view_docs), "can_totals": bool(m.can_view_totals), "can_edit": bool(m.can_edit_entries)}

# ---------- document vault ----------
def vault(u=Depends(me)):
    if not (u.role == "admin" or u.can_docs): raise HTTPException(403, "Ask the admin for document access")
    return u

@app.get("/api/documents")
def list_docs(u=Depends(vault), db=Depends(get_db)):
    return [row(x) for x in db.query(Doc).filter_by(project_id=u.project_id).order_by(Doc.id.desc())]

@app.post("/api/documents")
def add_doc(title: str = Form(...), file: UploadFile = File(...), u=Depends(admin), db=Depends(get_db)):
    d = Doc(project_id=u.project_id, title=title, file=save(file), by=u.nickname); db.add(d); db.commit(); return row(d)

@app.get("/api/documents/{did}/file")
def doc_file(did: int, u=Depends(vault), db=Depends(get_db)):
    d = db.get(Doc, did)
    if not d or d.project_id != u.project_id: raise HTTPException(404, "Not found")
    return FileResponse(os.path.join(UP, d.file))

@app.get("/")
def index(): return FileResponse("index.html")
