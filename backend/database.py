from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from config import settings

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    sessions = relationship("Session", back_populates="user")

class WorkspaceImage(Base):
    __tablename__ = "workspace_images"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True) # Docker image name
    friendly_name = Column(String)
    description = Column(String, nullable=True)
    category = Column(String, default="General")
    icon = Column(String, nullable=True) # URL or class name
    enabled = Column(Boolean, default=True)

    sessions = relationship("Session", back_populates="workspace_image")

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    workspace_image_id = Column(Integer, ForeignKey("workspace_images.id"))
    container_id = Column(String, unique=True)
    container_name = Column(String, unique=True)
    vnc_port = Column(Integer)
    vnc_password = Column(String) # Password for the VNC session
    status = Column(String, default="starting") # starting, running, stopped
    created_at = Column(DateTime, default=datetime.utcnow)
    last_accessed = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="sessions")
    workspace_image = relationship("WorkspaceImage", back_populates="sessions")

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    value = Column(String)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
