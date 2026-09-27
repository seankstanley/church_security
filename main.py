import asyncio
import datetime
import hashlib
import os
import re
import secrets
import ssl
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from typing import List, Optional
import urllib.request

from fastapi import FastAPI, HTTPException, Depends, Header, Query, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ---------------------------------------------------------------------------
# Database Configuration & ORM Models
# ---------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./church_security.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    church_org = Column(String, nullable=False)
    requested_role = Column(String, default="Security Team Member")
    role = Column(String, default="User")  # "Admin" or "User"
    is_approved = Column(Boolean, default=False)
    token = Column(String, nullable=True, index=True)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    inc_code = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)
    level = Column(String, nullable=False)
    church_name = Column(String, nullable=False)
    exact_location = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    image_url = Column(String, nullable=True)
    media_type = Column(String, default="image")
    reporter_name = Column(String, nullable=False)
    author_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class RssCacheModel(Base):
    __tablename__ = "rss_cache"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    state = Column(String, nullable=False)
    link = Column(String, nullable=False)
    summary = Column(Text, nullable=False)
    pub_date_str = Column(String, nullable=False)
    fetched_at = Column(DateTime, default=datetime.datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------
class UserRegisterRequest(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    church_org: str
    requested_role: Optional[str] = "Security Team Member"


class AdminCreateUserRequest(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    church_org: str
    role: Optional[str] = "User"
    requested_role: Optional[str] = "Security Team Member"


class AdminChangePasswordRequest(BaseModel):
    new_password: str


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    church_org: str
    requested_role: Optional[str] = "Security Team Member"
    role: str
    is_approved: bool

    class Config:
        from_attributes = True


class IncidentCreateRequest(BaseModel):
    title: str
    category: str
    level: str
    church_name: str
    exact_location: str
    description: str
    image_url: Optional[str] = None
    media_type: Optional[str] = "image"


class IncidentUpdateRequest(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    level: Optional[str] = None
    church_name: Optional[str] = None
    exact_location: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    media_type: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    inc_code: str
    title: str
    category: str
    level: str
    church_name: str
    exact_location: str
    description: str
    image_url: Optional[str]
    media_type: Optional[str] = "image"
    reporter_name: str
    author_id: int
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class RssItemResponse(BaseModel):
    id: int
    title: str
    state: str
    link: str
    summary: str
    pub_date_str: str

    class Config:
        from_attributes = True

def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with salt."""
    salt = "ChurchThreatMonitorSalt2026"
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()


def generate_token() -> str:
    """Generate a random bearer token for session identification."""
    return secrets.token_hex(32)


def get_db():
    """Dependency helper to yield database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> UserModel:
    """Retrieve the logged in user from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token"
        )
    
    token = authorization.split(" ")[1]
    user = db.query(UserModel).filter(UserModel.token == token).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token session")
    if not user.is_approved:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account pending admin approval")
    
    return user


def require_admin(current_user: UserModel = Depends(get_current_user)) -> UserModel:
    """Guard dependency requiring Administrator role privileges."""
    if current_user.role != "Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action restricted to Administrators only"
        )
    return current_user

def fetch_and_parse_rss_feed(db: Session) -> int:
    """Fetch live XML feed from Christian Warrior Training with SSL verification bypass."""
    feed_url = "https://intel.christianwarriortraining.com/feed.xml"
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(feed_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ChurchSecurityMonitor/1.0'})
        with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as response:
            xml_data = response.read()

        root = ET.fromstring(xml_data)
        channel = root.find('channel')
        if channel is None:
            return 0

        # Clear existing cached RSS items
        db.query(RssCacheModel).delete()

        count = 0
        items = channel.findall('item')
        for item in items[:15]:
            title = item.findtext('title', 'Threat Advisory')
            link = item.findtext('link', 'https://intel.christianwarriortraining.com')
            description = item.findtext('description', '')
            pub_date = item.findtext('pubDate', 'Recent')

            # Clean HTML tags from summary
            clean_summary = re.sub(r'<[^>]+>', '', description).strip()[:200]
            if len(clean_summary) == 200:
                clean_summary += "..."

            # Infer state tag from content text
            content_upper = (title + " " + clean_summary).upper()
            state_tag = "USA"
            if "GEORGIA" in content_upper or " GA " in content_upper or ", GA" in content_upper:
                state_tag = "GA"
            elif "SOUTH CAROLINA" in content_upper or " SC " in content_upper or ", SC" in content_upper:
                state_tag = "SC"

            rss_item = RssCacheModel(
                title=title,
                state=state_tag,
                link=link,
                summary=clean_summary if clean_summary else "No additional summary details provided.",
                pub_date_str=pub_date,
            )
            db.add(rss_item)
            count += 1

        db.commit()
        return count
    except Exception as e:
        print(f"Error syncing RSS feed: {e}")
        db.rollback()
        return 0

async def scheduled_rss_sync_loop():
    """Background worker fetching RSS feed every 12 hours (43200 seconds)."""
    while True:
        try:
            db = SessionLocal()
            fetch_and_parse_rss_feed(db)
            db.close()
        except Exception as e:
            print(f"Background RSS sync error: {e}")
        await asyncio.sleep(43200)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern FastAPI lifespan context manager replacing deprecated on_event."""
    db = SessionLocal()
    try:
        # Seed default administrator if none exists
        admin = db.query(UserModel).filter(UserModel.username == "admin").first()
        if not admin:
            default_admin = UserModel(
                username="admin",
                full_name="Admin Commander",
                email="admin@churchsecurity.org",
                hashed_password=hash_password("Admin123!"),
                church_org="Central Security Command",
                requested_role="Administrator",
                role="Admin",
                is_approved=True,
                token=generate_token()
            )
            db.add(default_admin)
            db.commit()

        # Initial RSS Sync
        fetch_and_parse_rss_feed(db)
    finally:
        db.close()

    # Start background task loop
    sync_task = asyncio.create_task(scheduled_rss_sync_loop())
    yield
    sync_task.cancel()

app = FastAPI(
    title="Church Threat & Incident Monitor API",
    description="Backend service providing authentication, RSS threat intel proxying, and incident logging.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Set to False when using allow_origins=["*"] with Bearer tokens
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    """Serve index.html at root URL or return API status."""
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {
        "status": "online",
        "message": "Church Threat Monitor API is running. Make sure index.html is in the same directory.",
        "docs": "/docs"
    }


@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_account(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """Request a new user account (Requires Admin approval)."""
    existing_user = db.query(UserModel).filter(
        (UserModel.username == payload.username) | (UserModel.email == payload.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already registered.")

    new_user = UserModel(
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        church_org=payload.church_org,
        requested_role=payload.requested_role,
        role="User",
        is_approved=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/api/auth/login")
def login(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and return bearer access token."""
    user = db.query(UserModel).filter(UserModel.username == payload.username).first()
    
    if not user or user.hashed_password != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not user.is_approved:
        raise HTTPException(status_code=403, detail="Account request is pending Administrator approval")

    # Refresh bearer token
    user.token = generate_token()
    db.commit()

    return {
        "access_token": user.token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "church_org": user.church_org
        }
    }


@app.get("/api/auth/me", response_model=UserResponse)
def get_profile(current_user: UserModel = Depends(get_current_user)):
    """Get current user authentication profile."""
    return current_user

@app.get("/api/admin/pending-users", response_model=List[UserResponse])
def get_pending_users(db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Fetch list of user accounts waiting for Administrator approval."""
    return db.query(UserModel).filter(UserModel.is_approved == False).all()


@app.get("/api/admin/users", response_model=List[UserResponse])
def list_all_users(db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Fetch all users in the system."""
    return db.query(UserModel).all()


@app.post("/api/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def admin_create_user(payload: AdminCreateUserRequest, db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Create a new pre-approved user account directly."""
    existing_user = db.query(UserModel).filter(
        (UserModel.username == payload.username) | (UserModel.email == payload.email)
    ).first()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already exists.")

    new_user = UserModel(
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        church_org=payload.church_org,
        requested_role=payload.requested_role,
        role=payload.role if payload.role in ["Admin", "User"] else "User",
        is_approved=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.put("/api/admin/users/{user_id}/password")
def admin_change_password(user_id: int, payload: AdminChangePasswordRequest, db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Change password for a specific user."""
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if len(payload.new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters long.")

    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"message": f"Password updated for user '{user.username}'."}


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Delete a user account."""
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own admin account.")
    
    db.delete(user)
    db.commit()
    return {"message": f"User '{user.username}' deleted successfully."}


@app.post("/api/admin/users/{user_id}/approve")
def approve_user(user_id: int, db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Approve a pending user account."""
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_approved = True
    db.commit()
    return {"message": f"User '{user.full_name}' approved successfully."}


@app.post("/api/admin/users/{user_id}/reject")
def reject_user(user_id: int, db: Session = Depends(get_db), admin: UserModel = Depends(require_admin)):
    """Reject and remove a requested user account."""
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"message": "Account request rejected and removed."}

@app.get("/api/rss", response_model=List[RssItemResponse])
def get_rss_feed(state: Optional[str] = Query(None), db: Session = Depends(get_db)):
    """Fetch cached Threat Intel Feed items with optional state filtering (GA, SC, USA)."""
    query = db.query(RssCacheModel)
    if state and state.upper() in ["GA", "SC"]:
        query = query.filter(RssCacheModel.state == state.upper())
    
    return query.order_by(RssCacheModel.fetched_at.desc()).all()


@app.post("/api/rss/refresh")
def force_refresh_rss(db: Session = Depends(get_db)):
    """Manually trigger RSS feed refresh from source."""
    count = fetch_and_parse_rss_feed(db)
    return {"message": "RSS Feed successfully refreshed", "items_fetched": count}

@app.get("/api/incidents", response_model=List[IncidentResponse])
def list_incidents(
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Retrieve list of incident reports with search and category filters."""
    query = db.query(IncidentModel)

    if category and category != "All":
        query = query.filter(IncidentModel.category == category)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (IncidentModel.title.ilike(search_term)) |
            (IncidentModel.church_name.ilike(search_term)) |
            (IncidentModel.exact_location.ilike(search_term)) |
            (IncidentModel.description.ilike(search_term))
        )

    return query.order_by(IncidentModel.created_at.desc()).all()


@app.post("/api/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Create a new incident report automatically attributed to logged-in user."""
    ts_suffix = int(datetime.datetime.utcnow().timestamp()) % 100000
    rand_suffix = secrets.randbelow(900) + 100
    inc_code = f"INC-{ts_suffix}-{rand_suffix}"

    new_inc = IncidentModel(
        inc_code=inc_code,
        title=payload.title,
        category=payload.category,
        level=payload.level,
        church_name=payload.church_name,
        exact_location=payload.exact_location,
        description=payload.description,
        image_url=payload.image_url,
        media_type=payload.media_type or "image",
        reporter_name=f"{current_user.full_name} ({current_user.requested_role or 'Security Team'})",
        author_id=current_user.id
    )
    db.add(new_inc)
    db.commit()
    db.refresh(new_inc)
    return new_inc


@app.put("/api/incidents/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    payload: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Update an incident report (Allowed for report author or Administrator)."""
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident report not found")

    if current_user.role != "Admin" and inc.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="You do not have permission to edit this report")

    if payload.title:
        inc.title = payload.title
    if payload.category:
        inc.category = payload.category
    if payload.level:
        inc.level = payload.level
    if payload.church_name:
        inc.church_name = payload.church_name
    if payload.exact_location:
        inc.exact_location = payload.exact_location
    if payload.description:
        inc.description = payload.description
    if payload.image_url is not None:
        inc.image_url = payload.image_url
    if payload.media_type is not None:
        inc.media_type = payload.media_type

    db.commit()
    db.refresh(inc)
    return inc


@app.delete("/api/incidents/{incident_id}")
def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Delete an incident report (Allowed for report author or Administrator)."""
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident report not found")

    if current_user.role != "Admin" and inc.author_id != current_user.id:
        raise HTTPException(status_code=403, detail="You do not have permission to delete this report")

    db.delete(inc)
    db.commit()
    return {"message": f"Incident report INC-{inc.id} successfully deleted."}

@app.post("/api/upload")
async def upload_media(file: UploadFile = File(...), current_user: UserModel = Depends(get_current_user)):
    """Upload incident documentation photo or video attachment."""
    filename = f"{secrets.token_hex(8)}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    content_type = file.content_type or ""
    is_video = content_type.startswith("video/") or filename.lower().endswith(
        ('.mp4', '.mov', '.avi', '.mkv', '.webm', '.m4v', '.3gp')
    )
    media_type = "video" if is_video else "image"

    return {
        "image_url": f"/static/uploads/{filename}",
        "media_type": media_type
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)