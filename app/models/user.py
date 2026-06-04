from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(String, default="student")  # admin, teacher, student
    google_id = Column(String, unique=True, index=True, nullable=True)
    telegram_id = Column(String, unique=True, index=True, nullable=True)
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    # Password-reset flow
    password_reset_token = Column(String, nullable=True, index=True)
    password_reset_expires = Column(DateTime, nullable=True)

    # Relationships
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    history = relationship("UserHistory", back_populates="user", cascade="all, delete-orphan")


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)

    user = relationship("User", back_populates="profile")


class UserHistory(Base):
    __tablename__ = "user_histories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    question = Column(String, nullable=False)
    data = Column(JSON, nullable=False)  # Stores array of HTML strings/elements (1-5 or more)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="history")

