import os, json, base64, uuid, shutil
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, Column, String, Integer, Float, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./policyguard.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.environ.get("SECRET_KEY", "policyguard-dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─── Database Models ───
class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    documents = relationship("DocumentDB", back_populates="user", cascade="all, delete-orphan")
    inventory_items = relationship("InventoryItemDB", back_populates="user", cascade="all, delete-orphan")
    calendar_events = relationship("CalendarEventDB", back_populates="user", cascade="all, delete-orphan")
    analyses = relationship("AnalysisDB", back_populates="user", cascade="all, delete-orphan")

class DocumentDB(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    doc_type = Column(String, nullable=False)
    policy_subtype = Column(String)
    label = Column(String, nullable=False)
    size = Column(Integer)
    mime_type = Column(String)
    file_path = Column(String)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="stored")
    user = relationship("UserDB", back_populates="documents")

class InventoryItemDB(Base):
    __tablename__ = "inventory_items"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    room = Column(String)
    category = Column(String)
    estimated_value = Column(Float, default=0)
    purchase_price = Column(Float, default=0)
    purchase_date = Column(String)
    serial_number = Column(String)
    notes = Column(Text)
    photo_path = Column(String)
    receipt_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("UserDB", back_populates="inventory_items")

class CalendarEventDB(Base):
    __tablename__ = "calendar_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    event_type = Column(String)
    event_date = Column(String, nullable=False)
    reminder_days = Column(Integer, default=7)
    notes = Column(Text)
    source_document = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("UserDB", back_populates="calendar_events")

class AnalysisDB(Base):
    __tablename__ = "analyses"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    document_id = Column(String, nullable=False)
    analysis_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("UserDB", back_populates="analyses")

Base.metadata.create_all(bind=engine)

# ─── Auth ───
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def create_token(user_id: str):
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None: raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if user is None: raise HTTPException(status_code=401, detail="User not found")
    return user

# ─── Pydantic Models ───
class UserCreate(BaseModel):
    email: str
    name: str
    password: str

class UserOut(BaseModel):
    id: str
    email: str
    name: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class DocumentOut(BaseModel):
    id: str
    name: str
    doc_type: str
    policy_subtype: Optional[str]
    label: str
    size: Optional[int]
    mime_type: Optional[str]
    uploaded_at: str
    status: str

class InventoryItemCreate(BaseModel):
    name: str
    room: Optional[str] = "Other"
    category: Optional[str] = "Other"
    estimated_value: Optional[float] = 0
    purchase_price: Optional[float] = 0
    purchase_date: Optional[str] = ""
    serial_number: Optional[str] = ""
    notes: Optional[str] = ""
    receipt_id: Optional[str] = None

class InventoryItemOut(BaseModel):
    id: str
    name: str
    room: str
    category: str
    estimated_value: float
    purchase_price: float
    purchase_date: str
    serial_number: str
    notes: str
    photo_path: Optional[str]
    receipt_id: Optional[str]
    created_at: str
    updated_at: str

class CalendarEventCreate(BaseModel):
    title: str
    event_type: Optional[str] = "other"
    event_date: str
    reminder_days: Optional[int] = 7
    notes: Optional[str] = ""
    source_document: Optional[str] = ""

class CalendarEventOut(BaseModel):
    id: str
    title: str
    event_type: str
    event_date: str
    reminder_days: int
    notes: str
    source_document: str
    created_at: str

class AnalysisCreate(BaseModel):
    document_id: str
    analysis_json: str

class AnalysisOut(BaseModel):
    id: str
    document_id: str
    analysis_json: str
    created_at: str

# ─── App ───
app = FastAPI(title="PolicyGuard API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ─── Auth Endpoints ───
@app.post("/api/auth/register", response_model=TokenOut)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserDB(email=user_data.email, name=user_data.name, password_hash=pwd_context.hash(user_data.password))
    db.add(user); db.commit(); db.refresh(user)
    token = create_token(user.id)
    return TokenOut(access_token=token, token_type="bearer", user=UserOut(id=user.id, email=user.email, name=user.name))

@app.post("/api/auth/login", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(user.id)
    return TokenOut(access_token=token, token_type="bearer", user=UserOut(id=user.id, email=user.email, name=user.name))

@app.get("/api/auth/me", response_model=UserOut)
def get_me(user: UserDB = Depends(get_current_user)):
    return UserOut(id=user.id, email=user.email, name=user.name)

# ─── Document Endpoints ───
@app.post("/api/documents", response_model=DocumentOut)
async def upload_document(
    file: UploadFile = File(...),
    doc_type: str = Form("other"),
    policy_subtype: str = Form(None),
    label: str = Form(None),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1]
    file_path = os.path.join(UPLOAD_DIR, user.id, file_id + ext)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    doc = DocumentDB(
        user_id=user.id, name=file.filename, doc_type=doc_type,
        policy_subtype=policy_subtype, label=label or file.filename,
        size=len(content), mime_type=file.content_type, file_path=file_path,
        status="pending_analysis" if doc_type == "policy" else "stored"
    )
    db.add(doc); db.commit(); db.refresh(doc)
    return DocumentOut(id=doc.id, name=doc.name, doc_type=doc.doc_type, policy_subtype=doc.policy_subtype, label=doc.label, size=doc.size, mime_type=doc.mime_type, uploaded_at=doc.uploaded_at.isoformat(), status=doc.status)

@app.get("/api/documents", response_model=List[DocumentOut])
def list_documents(user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    docs = db.query(DocumentDB).filter(DocumentDB.user_id == user.id).order_by(DocumentDB.uploaded_at.desc()).all()
    return [DocumentOut(id=d.id, name=d.name, doc_type=d.doc_type, policy_subtype=d.policy_subtype, label=d.label, size=d.size, mime_type=d.mime_type, uploaded_at=d.uploaded_at.isoformat(), status=d.status) for d in docs]

@app.get("/api/documents/{doc_id}/file")
def get_document_file(doc_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentDB).filter(DocumentDB.id == doc_id, DocumentDB.user_id == user.id).first()
    if not doc: raise HTTPException(status_code=404, detail="Document not found")
    return FileResponse(doc.file_path, media_type=doc.mime_type, filename=doc.name)

@app.get("/api/documents/{doc_id}/base64")
def get_document_base64(doc_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentDB).filter(DocumentDB.id == doc_id, DocumentDB.user_id == user.id).first()
    if not doc: raise HTTPException(status_code=404, detail="Document not found")
    with open(doc.file_path, "rb") as f:
        data = base64.b64encode(f.read()).decode("utf-8")
    return {"base64": data, "mime_type": doc.mime_type}

@app.delete("/api/documents/{doc_id}")
def delete_document(doc_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentDB).filter(DocumentDB.id == doc_id, DocumentDB.user_id == user.id).first()
    if not doc: raise HTTPException(status_code=404, detail="Document not found")
    if doc.file_path and os.path.exists(doc.file_path): os.remove(doc.file_path)
    db.delete(doc); db.commit()
    return {"ok": True}

@app.patch("/api/documents/{doc_id}/status")
def update_document_status(doc_id: str, status: str = Form(...), user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(DocumentDB).filter(DocumentDB.id == doc_id, DocumentDB.user_id == user.id).first()
    if not doc: raise HTTPException(status_code=404, detail="Document not found")
    doc.status = status; db.commit()
    return {"ok": True}

# ─── Inventory Endpoints ───
@app.post("/api/inventory", response_model=InventoryItemOut)
def create_inventory_item(item: InventoryItemCreate, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_item = InventoryItemDB(user_id=user.id, name=item.name, room=item.room, category=item.category, estimated_value=item.estimated_value, purchase_price=item.purchase_price, purchase_date=item.purchase_date, serial_number=item.serial_number, notes=item.notes, receipt_id=item.receipt_id)
    db.add(db_item); db.commit(); db.refresh(db_item)
    return _item_out(db_item)

@app.get("/api/inventory", response_model=List[InventoryItemOut])
def list_inventory(user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(InventoryItemDB).filter(InventoryItemDB.user_id == user.id).order_by(InventoryItemDB.created_at.desc()).all()
    return [_item_out(i) for i in items]

@app.put("/api/inventory/{item_id}", response_model=InventoryItemOut)
def update_inventory_item(item_id: str, item: InventoryItemCreate, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_item = db.query(InventoryItemDB).filter(InventoryItemDB.id == item_id, InventoryItemDB.user_id == user.id).first()
    if not db_item: raise HTTPException(status_code=404, detail="Item not found")
    for k, v in item.dict().items(): setattr(db_item, k, v)
    db_item.updated_at = datetime.utcnow()
    db.commit(); db.refresh(db_item)
    return _item_out(db_item)

@app.post("/api/inventory/{item_id}/photo")
async def upload_inventory_photo(item_id: str, file: UploadFile = File(...), user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_item = db.query(InventoryItemDB).filter(InventoryItemDB.id == item_id, InventoryItemDB.user_id == user.id).first()
    if not db_item: raise HTTPException(status_code=404, detail="Item not found")
    file_path = os.path.join(UPLOAD_DIR, user.id, "inventory", item_id + os.path.splitext(file.filename)[1])
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f: f.write(await file.read())
    db_item.photo_path = file_path; db_item.updated_at = datetime.utcnow()
    db.commit()
    return {"photo_path": file_path}

@app.get("/api/inventory/{item_id}/photo")
def get_inventory_photo(item_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_item = db.query(InventoryItemDB).filter(InventoryItemDB.id == item_id, InventoryItemDB.user_id == user.id).first()
    if not db_item or not db_item.photo_path: raise HTTPException(status_code=404)
    return FileResponse(db_item.photo_path)

@app.delete("/api/inventory/{item_id}")
def delete_inventory_item(item_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_item = db.query(InventoryItemDB).filter(InventoryItemDB.id == item_id, InventoryItemDB.user_id == user.id).first()
    if not db_item: raise HTTPException(status_code=404)
    db.delete(db_item); db.commit()
    return {"ok": True}

def _item_out(i):
    return InventoryItemOut(id=i.id, name=i.name, room=i.room or "", category=i.category or "", estimated_value=i.estimated_value or 0, purchase_price=i.purchase_price or 0, purchase_date=i.purchase_date or "", serial_number=i.serial_number or "", notes=i.notes or "", photo_path=i.photo_path, receipt_id=i.receipt_id, created_at=i.created_at.isoformat(), updated_at=i.updated_at.isoformat())

# ─── Calendar Endpoints ───
@app.post("/api/calendar", response_model=CalendarEventOut)
def create_event(event: CalendarEventCreate, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_event = CalendarEventDB(user_id=user.id, title=event.title, event_type=event.event_type, event_date=event.event_date, reminder_days=event.reminder_days, notes=event.notes, source_document=event.source_document)
    db.add(db_event); db.commit(); db.refresh(db_event)
    return _event_out(db_event)

@app.get("/api/calendar", response_model=List[CalendarEventOut])
def list_events(user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    events = db.query(CalendarEventDB).filter(CalendarEventDB.user_id == user.id).order_by(CalendarEventDB.event_date).all()
    return [_event_out(e) for e in events]

@app.put("/api/calendar/{event_id}", response_model=CalendarEventOut)
def update_event(event_id: str, event: CalendarEventCreate, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_event = db.query(CalendarEventDB).filter(CalendarEventDB.id == event_id, CalendarEventDB.user_id == user.id).first()
    if not db_event: raise HTTPException(status_code=404)
    for k, v in event.dict().items(): setattr(db_event, k, v)
    db.commit(); db.refresh(db_event)
    return _event_out(db_event)

@app.delete("/api/calendar/{event_id}")
def delete_event(event_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_event = db.query(CalendarEventDB).filter(CalendarEventDB.id == event_id, CalendarEventDB.user_id == user.id).first()
    if not db_event: raise HTTPException(status_code=404)
    db.delete(db_event); db.commit()
    return {"ok": True}

def _event_out(e):
    return CalendarEventOut(id=e.id, title=e.title, event_type=e.event_type or "", event_date=e.event_date, reminder_days=e.reminder_days or 0, notes=e.notes or "", source_document=e.source_document or "", created_at=e.created_at.isoformat())

# ─── Analysis Endpoints ───
@app.post("/api/analyses", response_model=AnalysisOut)
def save_analysis(analysis: AnalysisCreate, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(AnalysisDB).filter(AnalysisDB.document_id == analysis.document_id, AnalysisDB.user_id == user.id).first()
    if existing:
        existing.analysis_json = analysis.analysis_json; db.commit(); db.refresh(existing)
        return _analysis_out(existing)
    db_analysis = AnalysisDB(user_id=user.id, document_id=analysis.document_id, analysis_json=analysis.analysis_json)
    db.add(db_analysis); db.commit(); db.refresh(db_analysis)
    return _analysis_out(db_analysis)

@app.get("/api/analyses", response_model=List[AnalysisOut])
def list_analyses(user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    analyses = db.query(AnalysisDB).filter(AnalysisDB.user_id == user.id).all()
    return [_analysis_out(a) for a in analyses]

@app.get("/api/analyses/{doc_id}", response_model=AnalysisOut)
def get_analysis(doc_id: str, user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.query(AnalysisDB).filter(AnalysisDB.document_id == doc_id, AnalysisDB.user_id == user.id).first()
    if not a: raise HTTPException(status_code=404)
    return _analysis_out(a)

def _analysis_out(a):
    return AnalysisOut(id=a.id, document_id=a.document_id, analysis_json=a.analysis_json, created_at=a.created_at.isoformat())

# ─── Health Check ───
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PolicyGuard API"}
