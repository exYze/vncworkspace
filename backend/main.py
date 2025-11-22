from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
import asyncio
import logging

from config import settings
from database import get_db, init_db, User, WorkspaceImage, Session, SystemSetting, AsyncSessionLocal
from docker_manager import docker_manager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="VNC Workspace Manager")

# ... (omitted for brevity, but I need to be careful with replace_file_content)
# Actually, I should do this in chunks.

# Chunk 1: Update imports


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET_KEY)

# OAuth Setup
# OAuth Setup
oauth = OAuth()
oauth.register(
    name='authentik',
    client_id=settings.AUTHENTIK_CLIENT_ID,
    client_secret=settings.AUTHENTIK_CLIENT_SECRET,
    # We manually configure endpoints because of the split-horizon DNS issue:
    # Backend needs to talk to 'authentik-server:9000' (Internal)
    # Browser needs to talk to 'localhost:9000' (Public)
    authorize_url=f'{settings.AUTHENTIK_PUBLIC_URL}/application/o/authorize/',
    access_token_url=f'{settings.AUTHENTIK_SERVER_URL}/application/o/token/',
    userinfo_endpoint=f'{settings.AUTHENTIK_SERVER_URL}/application/o/userinfo/',
    jwks_uri=f'{settings.AUTHENTIK_SERVER_URL}/application/o/vnc-manager/jwks/',
    client_kwargs={
        'scope': 'openid profile email',
    }
)

# Auth Utils
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: Optional[str] = None
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    is_admin: bool
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class WorkspaceImageCreate(BaseModel):
    name: str
    friendly_name: str
    description: Optional[str] = None
    category: str = "General"
    icon: Optional[str] = None
    enabled: bool = True

class WorkspaceImageResponse(WorkspaceImageCreate):
    id: int

    class Config:
        from_attributes = True

class SessionResponse(BaseModel):
    id: int
    vnc_port: int
    vnc_password: Optional[str] = None # Add password field
    status: str
    created_at: datetime
    user_id: int
    workspace_image_id: int
    container_name: str
    vnc_port: int
    status: str
    created_at: datetime
    workspace_image: Optional[WorkspaceImageResponse] = None
    user: Optional[UserResponse] = None

    class Config:
        from_attributes = True

class SessionStart(BaseModel):
    workspace_image_id: int

class SystemSettingUpdate(BaseModel):
    value: str

# Background Tasks
async def check_session_timeouts():
    while True:
        try:
            async with AsyncSessionLocal() as db:
                # Check for expired sessions
                # For now, just a placeholder or simple check
                pass
        except Exception as e:
            logger.error(f"Error in background task: {e}")
        await asyncio.sleep(60)

# Startup
@app.on_event("startup")
async def startup_event():
    await init_db()
    
    # Create default users and workspaces
    async with AsyncSessionLocal() as db:
        # Check if admin exists
        result = await db.execute(select(User).where(User.username == settings.ADMIN_USERNAME))
        admin = result.scalars().first()
        if not admin:
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                is_admin=True
            )
            db.add(admin_user)
        
        # Check if student exists
        result = await db.execute(select(User).where(User.username == settings.STUDENT_USERNAME))
        student = result.scalars().first()
        if not student:
            student_user = User(
                username=settings.STUDENT_USERNAME,
                hashed_password=get_password_hash(settings.STUDENT_PASSWORD),
                is_admin=False
            )
            db.add(student_user)

        # Default Workspaces
        result = await db.execute(select(WorkspaceImage).where(WorkspaceImage.name == "kasmweb/ubuntu-jammy-desktop:1.17.0"))
        ws = result.scalars().first()
        if not ws:
            db.add(WorkspaceImage(
                name="kasmweb/ubuntu-jammy-desktop:1.17.0",
                friendly_name="Ubuntu Desktop",
                description="Ubuntu 22.04 LTS with KasmVNC",
                category="Linux",
                icon="fa-brands fa-ubuntu"
            ))
        
        result = await db.execute(select(WorkspaceImage).where(WorkspaceImage.name == "kasmweb/kali-rolling-desktop:1.17.0"))
        ws = result.scalars().first()
        if not ws:
            db.add(WorkspaceImage(
                name="kasmweb/kali-rolling-desktop:1.17.0",
                friendly_name="Kali Linux",
                description="Kali Linux for Security Research",
                category="Security",
                icon="fa-solid fa-shield-halved"
            ))

        # Default Settings
        result = await db.execute(select(SystemSetting).where(SystemSetting.key == "session_timeout_minutes"))
        setting = result.scalars().first()
        if not setting:
            db.add(SystemSetting(
                key="session_timeout_minutes",
                value="60",
                description="Session timeout in minutes"
            ))

        await db.commit()

# API Routes

# Auth
@app.post("/api/auth/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/register", response_model=UserResponse)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == user.username))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@app.get("/api/auth/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# OIDC Routes
@app.get("/api/auth/login/authentik")
async def login_authentik(request: Request):
    redirect_uri = request.url_for('auth_authentik_callback')
    # Ensure we are using the correct scheme/host if behind proxy, but for now use what request sees
    # If behind nginx, X-Forwarded-Proto should be handled by ProxyHeadersMiddleware (not added yet, but good to know)
    # For local dev, http is fine.
    # We need to make sure the redirect_uri matches what is registered in Authentik
    # Since we are running on port 8000 internally but 8080 externally, we might need to hardcode or adjust
    # For this setup, the user hits nginx at 8080.
    redirect_uri = "http://localhost:8080/api/auth/callback/authentik"
    return await oauth.authentik.authorize_redirect(request, redirect_uri)

@app.get("/api/auth/callback/authentik")
async def auth_authentik_callback(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.authentik.authorize_access_token(request)
        user_info = token.get('userinfo')
        if not user_info:
             # Try to fetch userinfo if not in token
             user_info = await oauth.authentik.userinfo(token=token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OIDC Error: {str(e)}")

    logger.info(f"Authentik User Info: {user_info}")
    username = user_info.get('preferred_username', user_info.get('nickname', user_info.get('sub')))
    email = user_info.get('email')
    
    # Check if user exists
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    
    if not user:
        # Create user
        # We don't have a password, so we set an unusable one or handle it differently.
        # For now, we just set a random hash.
        user = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(settings.SESSION_SECRET_KEY + username), # Placeholder
            is_active=True
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Redirect to frontend with token
    return RedirectResponse(url=f"http://localhost:8080/?token={access_token}")

# Workspaces
@app.get("/api/workspaces", response_model=List[WorkspaceImageResponse])
async def get_workspaces(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    result = await db.execute(select(WorkspaceImage).where(WorkspaceImage.enabled == True))
    return result.scalars().all()

# Sessions
@app.get("/api/sessions/status", response_model=Optional[SessionResponse])
async def get_session_status(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    result = await db.execute(
        select(Session)
        .options(selectinload(Session.workspace_image))
        .where(Session.user_id == current_user.id)
        .where(Session.status == "running")
    )
    session = result.scalars().first()
    
    if session:
        # Update last accessed
        session.last_accessed = datetime.utcnow()
        await db.commit()
        
        # Check if container is actually running
        status = docker_manager.get_container_status(session.container_id)
        if status != "running":
            session.status = "stopped"
            await db.commit()
            return None
            
    return session

@app.post("/api/sessions/start", response_model=SessionResponse)
async def start_session(
    session_start: SessionStart, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # Check if user already has a session
    result = await db.execute(select(Session).where(Session.user_id == current_user.id).where(Session.status == "running"))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="User already has an active session")

    # Get workspace image
    workspace = await db.get(WorkspaceImage, session_start.workspace_image_id)
    if not workspace or not workspace.enabled:
        raise HTTPException(status_code=404, detail="Workspace not found or disabled")

    # Start container
    try:
        container_info = docker_manager.start_container(workspace.name, current_user.username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Create session record
    new_session = Session(
        user_id=current_user.id,
        workspace_image_id=workspace.id,
        container_id=container_info["container_id"],
        container_name=container_info["container_name"],
        vnc_port=container_info["vnc_port"],
        vnc_password=container_info.get("vnc_password"), # Save password
        status="running"
    )
    db.add(new_session)
    await db.commit()
    await db.refresh(new_session)
    
    # Re-fetch with relationship
    result = await db.execute(
        select(Session)
        .options(selectinload(Session.workspace_image))
        .where(Session.id == new_session.id)
    )
    return result.scalars().first()

@app.post("/api/sessions/stop")
async def stop_session(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    result = await db.execute(select(Session).where(Session.user_id == current_user.id).where(Session.status == "running"))
    session = result.scalars().first()
    
    if not session:
        raise HTTPException(status_code=404, detail="No active session found")

    try:
        docker_manager.stop_container(session.container_id)
    except Exception as e:
        logger.error(f"Error stopping container: {e}")
        # Continue to mark as stopped in DB even if docker fails (might be already stopped)

    session.status = "stopped"
    await db.commit()
    return {"message": "Session stopped"}

# Admin Routes
@app.get("/api/admin/users", response_model=List[UserResponse])
async def get_all_users(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(select(User))
    return result.scalars().all()

@app.post("/api/admin/users", response_model=UserResponse)
async def create_user_admin(user: UserCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    return await register_user(user, db)

@app.delete("/api/admin/users/{user_id}")
async def delete_user(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"message": "User deleted"}

@app.get("/api/admin/workspaces", response_model=List[WorkspaceImageResponse])
async def get_admin_workspaces(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(select(WorkspaceImage))
    return result.scalars().all()

@app.post("/api/admin/workspaces", response_model=WorkspaceImageResponse)
async def create_workspace(workspace: WorkspaceImageCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    new_ws = WorkspaceImage(**workspace.model_dump())
    db.add(new_ws)
    await db.commit()
    await db.refresh(new_ws)
    return new_ws

@app.get("/api/admin/sessions", response_model=List[SessionResponse])
async def get_all_sessions(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(
        select(Session)
        .options(selectinload(Session.user), selectinload(Session.workspace_image))
        .where(Session.status == "running")
    )
    return result.scalars().all()

@app.delete("/api/admin/sessions/{user_id}")
async def force_stop_session(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(select(Session).where(Session.user_id == user_id).where(Session.status == "running"))
    session = result.scalars().first()
    
    if not session:
        raise HTTPException(status_code=404, detail="No active session for this user")

    try:
        docker_manager.stop_container(session.container_id)
    except Exception as e:
        logger.error(f"Error stopping container: {e}")

    session.status = "stopped"
    await db.commit()
    return {"message": "Session force stopped"}

@app.get("/api/admin/settings")
async def get_settings(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(select(SystemSetting))
    settings_list = result.scalars().all()
    return {s.key: s.value for s in settings_list}

@app.post("/api/admin/settings/{key}")
async def update_setting(key: str, setting: SystemSettingUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    result = await db.execute(select(SystemSetting).where(SystemSetting.key == key))
    sys_setting = result.scalars().first()
    
    if not sys_setting:
        sys_setting = SystemSetting(key=key, value=setting.value)
        db.add(sys_setting)
    else:
        sys_setting.value = setting.value
        
    await db.commit()
    return {"message": "Setting updated"}

@app.get("/api/admin/stats")
async def get_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_admin_user)):
    total_users = await db.scalar(select(func.count(User.id)))
    total_workspaces = await db.scalar(select(func.count(WorkspaceImage.id)))
    active_sessions = await db.scalar(select(func.count(Session.id)).where(Session.status == "running"))
    total_sessions = await db.scalar(select(func.count(Session.id)))
    
    return {
        "total_users": total_users,
        "total_workspaces": total_workspaces,
        "active_sessions": active_sessions,
        "total_sessions": total_sessions
    }
