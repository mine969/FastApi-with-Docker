import os
import secrets
from datetime import timedelta
from typing import Optional

from fastapi import FastAPI, Request, Depends, Form, HTTPException, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, select
from sqlalchemy.orm import declarative_base, Session, sessionmaker
from passlib.context import CryptContext
import redis

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Redis client
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Login Demo with FastAPI + Redis", version="1.0")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_user(db: Session, username: str, password: str):
    hashed = pwd_context.hash(password)
    user = User(username=username, password_hash=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    stmt = select(User).where(User.username == username)
    user = db.execute(stmt).scalar_one_or_none()
    if not user:
        return None
    if not pwd_context.verify(password, user.password_hash):
        return None
    return user

def set_session_cookie(response: Response, session_id: str):
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=int(timedelta(days=1).total_seconds())
    )

def get_current_user(request: Request, db: Session) -> Optional[User]:
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    user_id = r.get(f"session:{session_id}")
    if not user_id:
        return None
    stmt = select(User).where(User.id == int(user_id))
    return db.execute(stmt).scalar_one_or_none()

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    create_user(db, username, password)
    resp = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return resp

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, username, password)
    if not user:
        # Return form with error
        html = templates.get_template("login.html").render({"request": {}, "error": "Invalid credentials"})
        return HTMLResponse(content=html, status_code=401)
    session_id = secrets.token_urlsafe(32)
    r.setex(f"session:{session_id}", int(timedelta(days=1).total_seconds()), user.id)
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(resp, session_id)
    return resp

@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        r.delete(f"session:{session_id}")
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie("session_id")
    return resp

@app.get("/protected", response_class=HTMLResponse)
def protected(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("protected.html", {"request": request, "user": user})
