import secrets
import logging
from datetime import datetime, timedelta
from typing import List

import pyotp
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)
from app.db.database import get_db
from app.models.user import User, UserProfile, UserHistory
from app.schemas.user import (
    ForgotPassword,
    ResetPassword,
    Token,
    TokenPayload,
    UserCreate,
    UserInDB,
    UserMFA,
    UserProfileUpdate,
    UserProfileInDB,
    UserHistoryCreate,
    UserHistoryInDB,
)
from app.utils.email import send_password_reset_email

logger = logging.getLogger(__name__)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ── Google OAuth client ────────────────────────────────────────────────────────
oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)


# ── Helpers ────────────────────────────────────────────────────────────────────
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_data = TokenPayload(**payload)
        if token_data.refresh:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).filter(User.id == int(token_data.sub)))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user


# ── Register ───────────────────────────────────────────────────────────────────
@router.post(
    "/register",
    response_model=UserInDB,
    summary="Register a new user",
    description="Creates a new user account with email + password. Fails if email already registered.",
)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == user_in.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_in.password)
    db_user = User(email=user_in.email, hashed_password=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


# ── Login ──────────────────────────────────────────────────────────────────────
@router.post(
    "/login",
    response_model=Token,
    summary="Login / Get Token",
    description="Authenticates with email+password. Returns JWT pair. If MFA is enabled returns token_type='mfa_required'.",
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).filter(User.email == form_data.username))
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    if user.mfa_enabled:
        return {"access_token": "", "refresh_token": "", "token_type": "mfa_required"}

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# ── MFA Login ─────────────────────────────────────────────────────────────────
@router.post(
    "/login/mfa",
    response_model=Token,
    summary="Verify MFA during Login",
    description="After normal login returns mfa_required, submit email + TOTP code here.",
)
async def login_mfa(mfa_data: UserMFA, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == mfa_data.email))
    user = result.scalars().first()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Invalid request")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_data.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# ── Refresh Token ──────────────────────────────────────────────────────────────
@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh Access Token",
    description="Exchange a valid refresh token for a new access token.",
)
async def refresh_token_endpoint(refresh_token: str, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_data = TokenPayload(**payload)
        if not token_data.refresh:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).filter(User.id == int(token_data.sub)))
    user = result.scalars().first()
    if not user or not user.is_active:
        raise credentials_exception

    access_token = create_access_token(subject=user.id, expires_delta=timedelta(minutes=15))
    new_refresh_token = create_refresh_token(subject=user.id)
    return {"access_token": access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


# ── Google OAuth ───────────────────────────────────────────────────────────────
@router.get(
    "/google/login",
    summary="Initiate Google OAuth login",
    description="Redirects the browser to Google's consent screen.",
)
async def google_login(request: Request):
    redirect_uri = request.url_for("google_auth")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get(
    "/google/auth",
    name="google_auth",
    summary="Google OAuth callback",
    description=(
        "Google redirects here after the user consents. "
        "The account's Google email is stored on the user record. "
        "Redirects the browser to FRONTEND_URL/auth/callback?access_token=...&refresh_token=...&email=..."
    ),
)
async def google_auth(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as exc:
        logger.error("Google OAuth error: %s", exc)
        raise HTTPException(status_code=400, detail="Could not authorize with Google")

    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(status_code=400, detail="Could not retrieve Google profile")

    email: str = user_info.get("email")
    google_id: str = user_info.get("sub")

    if not email:
        raise HTTPException(status_code=400, detail="Google account has no email")

    # Find or auto-create the user
    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()

    if not user:
        # New Google user — register automatically using the Google email.
        # Assign a random hashed password so forgot-password works if they
        # later want to log in directly with email+password.
        random_pw = secrets.token_urlsafe(32)
        user = User(
            email=email,
            hashed_password=get_password_hash(random_pw),
            google_id=google_id,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        # Link google_id if not yet stored
        if not user.google_id:
            user.google_id = google_id
            await db.commit()

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)

    # Redirect to frontend with tokens + the google email so the UI can pre-fill / confirm
    redirect_url = (
        f"{settings.FRONTEND_URL}/auth/callback"
        f"?access_token={access_token}"
        f"&refresh_token={refresh_token}"
        f"&token_type=bearer"
        f"&email={email}"
    )
    return RedirectResponse(url=redirect_url)


# ── Forgot Password ────────────────────────────────────────────────────────────
@router.post(
    "/forgot-password",
    summary="Request a password reset link",
    description=(
        "Sends a one-time reset link to the account's email address. "
        "The link is valid for PASSWORD_RESET_EXPIRE_MINUTES minutes. "
        "Always returns 200 to avoid user enumeration."
    ),
)
async def forgot_password(body: ForgotPassword, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.email == body.email))
    user = result.scalars().first()

    # Always return 200 — don't leak whether the email exists
    if not user:
        return {"msg": "If that email exists, a reset link has been sent."}

    # Generate a cryptographically random token
    reset_token = secrets.token_urlsafe(48)
    user.password_reset_token = reset_token
    user.password_reset_expires = datetime.utcnow() + timedelta(
        minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES
    )
    await db.commit()

    reset_link = f"{settings.FRONTEND_URL}/auth/reset-password?token={reset_token}"

    try:
        await send_password_reset_email(to_email=user.email, reset_link=reset_link)
    except Exception as exc:
        logger.error("Email send failed: %s", exc)
        # Don't expose SMTP errors to the caller
        return {"msg": "If that email exists, a reset link has been sent."}

    return {"msg": "If that email exists, a reset link has been sent."}


# ── Reset Password ─────────────────────────────────────────────────────────────
@router.post(
    "/reset-password",
    summary="Reset password using token from email",
    description="Supply the token from the reset email and a new password.",
)
async def reset_password(body: ResetPassword, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).filter(User.password_reset_token == body.token)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    if user.password_reset_expires is None or datetime.utcnow() > user.password_reset_expires:
        # Invalidate the stale token
        user.password_reset_token = None
        user.password_reset_expires = None
        await db.commit()
        raise HTTPException(status_code=400, detail="Reset token has expired")

    # Set new password + clear token
    user.hashed_password = get_password_hash(body.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    await db.commit()

    return {"msg": "Password updated successfully. You can now log in with your new password."}


# ── Telegram Auth ─────────────────────────────────────────────────────────────
@router.post(
    "/telegram/auth",
    summary="Telegram authentication",
    description="Link or create a user via Telegram ID. Hash verification should be added for production.",
)
async def telegram_auth(telegram_id: str, email: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.telegram_id == telegram_id))
    user = result.scalars().first()

    if not user:
        result = await db.execute(select(User).filter(User.email == email))
        user = result.scalars().first()
        if user:
            user.telegram_id = telegram_id
            await db.commit()
        else:
            random_pw = secrets.token_urlsafe(32)
            user = User(
                email=email,
                hashed_password=get_password_hash(random_pw),
                telegram_id=telegram_id,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

    access_token = create_access_token(subject=user.id)
    refresh_token = create_refresh_token(subject=user.id)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# ── MFA Setup / Verify ────────────────────────────────────────────────────────
@router.post(
    "/mfa/setup",
    summary="Setup MFA (Generate QR)",
    description="Generates a Base32 TOTP secret. Scan the URI with Google Authenticator / Authy.",
)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")

    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    await db.commit()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="FastAPI App"
    )
    return {"secret": secret, "uri": uri}


@router.post(
    "/mfa/verify",
    summary="Verify and Enable MFA",
    description="Submit 6-digit TOTP code after scanning QR. If correct, MFA is permanently enabled.",
)
async def verify_mfa(
    code: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not setup")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if totp.verify(code):
        current_user.mfa_enabled = True
        await db.commit()
        return {"msg": "MFA enabled"}
    raise HTTPException(status_code=400, detail="Invalid MFA code")


# ── RBAC ──────────────────────────────────────────────────────────────────────
def role_required(required_role: str):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return current_user
    return role_checker


@router.get("/admin", dependencies=[Depends(role_required("admin"))])
async def read_admin_data():
    return {"msg": "Admin data"}


@router.get("/teacher", dependencies=[Depends(role_required("teacher"))])
async def read_teacher_data():
    return {"msg": "Teacher data"}


@router.get(
    "/me",
    response_model=UserInDB,
    summary="Get Current User",
    description="Returns profile of the authenticated user.",
)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── User Profile Endpoints ───────────────────────────────────────────────────
@router.get(
    "/profile",
    response_model=UserProfileInDB,
    summary="Get User Profile",
    description="Retrieves the profile of the current user. Creates one if it does not exist.",
)
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserProfile).filter(UserProfile.user_id == current_user.id)
    )
    profile = result.scalars().first()
    if not profile:
        profile = UserProfile(user_id=current_user.id)
        db.add(profile)
        await db.commit()
        await db.refresh(profile)
    return profile


@router.put(
    "/profile",
    response_model=UserProfileInDB,
    summary="Update User Profile",
    description="Updates the profile of the current user.",
)
async def update_profile(
    profile_in: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserProfile).filter(UserProfile.user_id == current_user.id)
    )
    profile = result.scalars().first()
    if not profile:
        profile = UserProfile(user_id=current_user.id)
        db.add(profile)
        await db.commit()
        await db.refresh(profile)

    for field, value in profile_in.model_dump(exclude_unset=True).items():
        setattr(profile, field, value)

    await db.commit()
    await db.refresh(profile)
    return profile


# ── User History Endpoints ───────────────────────────────────────────────────
@router.post(
    "/history",
    response_model=UserHistoryInDB,
    summary="Create User History Record",
    description="Creates a new history record for the current user.",
)
async def create_history(
    history_in: UserHistoryCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    db_history = UserHistory(
        user_id=current_user.id,
        question=history_in.question,
        data=history_in.data,
    )
    db.add(db_history)
    await db.commit()
    await db.refresh(db_history)
    return db_history


@router.get(
    "/history",
    response_model=List[UserHistoryInDB],
    summary="Get User History",
    description="Retrieves history records for the current user, ordered by creation time descending, with start/end slice pagination.",
)
async def get_history(
    start: int = 0,
    end: int = 3,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if end <= start:
        return []
    limit = end - start
    result = await db.execute(
        select(UserHistory)
        .filter(UserHistory.user_id == current_user.id)
        .order_by(UserHistory.created_at.desc())
        .offset(start)
        .limit(limit)
    )
    histories = result.scalars().all()
    return histories
