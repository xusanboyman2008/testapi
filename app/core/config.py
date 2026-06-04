from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "FastAPI Auth"
    SECRET_KEY: str = "super_secret_key_change_in_production_1234567890"
    SESSION_SECRET: str = "session_secret_change_in_production_xyz987"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    DATABASE_URL: str = "sqlite+aiosqlite:///./sql_app.db"

    # Frontend URL – where to redirect after Google OAuth and password reset links
    FRONTEND_URL: str = "http://localhost:3000"

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""

    # SMTP for password reset emails
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""          # set via .env: SMTP_USER=you@gmail.com
    SMTP_PASSWORD: str = ""      # set via .env: SMTP_PASSWORD=app_password
    SMTP_FROM: str = "noreply@example.com"

    # How long a password-reset link is valid (minutes)
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"

settings = Settings()
