import contextlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import settings
from app.db.database import engine, Base
from app.routers import auth


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FastAPI Auth", lifespan=lifespan)

# Configure CORS to allow frontend requests
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
    settings.FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Required by authlib to store OAuth state between /google/login and /google/auth
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

app.include_router(auth.router, prefix="/auth", tags=["auth"])


@app.get("/")
def root():
    return {"message": "Auth API Running. Check /docs."}
