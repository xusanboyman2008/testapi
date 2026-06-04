from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User's email address")

class UserCreate(UserBase):
    password: str = Field(..., description="Strong password", min_length=8)
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "hacker@example.com",
                "password": "supersecretpassword123"
            }
        }

class UserUpdate(BaseModel):
    password: Optional[str] = None
    is_active: Optional[bool] = None

class UserInDB(UserBase):
    id: int = Field(..., description="Unique user ID")
    is_active: bool = Field(..., description="Whether the user account is active")
    is_superuser: bool = Field(..., description="Admin flag")
    role: str = Field(..., description="User role, e.g. 'admin', 'teacher', 'user'")
    mfa_enabled: bool = Field(..., description="Is 2FA enabled for this user?")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "email": "hacker@example.com",
                "id": 1337,
                "is_active": True,
                "is_superuser": False,
                "role": "user",
                "mfa_enabled": False
            }
        }

class UserMFA(BaseModel):
    email: EmailStr
    code: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    refresh: bool = False

# Password reset schemas
class ForgotPassword(BaseModel):
    email: EmailStr = Field(..., description="Email address to send reset link to")

    class Config:
        json_schema_extra = {"example": {"email": "user@example.com"}}

class ResetPassword(BaseModel):
    token: str = Field(..., description="Reset token from the email link")
    new_password: str = Field(..., min_length=8, description="New password (min 8 chars)")

    class Config:
        json_schema_extra = {
            "example": {
                "token": "abc123resettoken",
                "new_password": "mynewpassword99"
            }
        }


# User Profile Schemas
class UserProfileBase(BaseModel):
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    bio: Optional[str] = Field(None, description="User biography")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")

class UserProfileUpdate(UserProfileBase):
    pass

class UserProfileInDB(UserProfileBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True


# User History Schemas
class UserHistoryCreate(BaseModel):
    question: str = Field(..., description="The query/question asked by the user")
    data: List[str] = Field(..., description="Array of HTML string responses (1-5 or more)")

class UserHistoryInDB(UserHistoryCreate):
    id: int
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True
