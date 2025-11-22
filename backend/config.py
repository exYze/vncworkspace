import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DATABASE_URL: str = "sqlite+aiosqlite:///./vnc_workspace.db"
    DOCKER_SOCKET_PATH: str = "unix:///var/run/docker.sock"
    
    # Default Admin User
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"
    
    # Default Student User
    STUDENT_USERNAME: str = "student"
    STUDENT_PASSWORD: str = "student"

    # Authentik Settings
    AUTHENTIK_CLIENT_ID: str = ""
    AUTHENTIK_CLIENT_SECRET: str = ""
    AUTHENTIK_SERVER_URL: str = "http://authentik-server:9000" # Internal URL for backend
    AUTHENTIK_PUBLIC_URL: str = "http://localhost:9000" # Public URL for browser
    SESSION_SECRET_KEY: str = "super-secret-session-key"

    class Config:
        env_file = ".env"

settings = Settings()
