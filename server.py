
# ==================== DSET BACKEND (ID-BASED USERS) ====================

from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os, uuid, logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
import jwt
import pandas as pd
from io import BytesIO

ROOT_DIR = Path(__file__).parent

# ==================== DATABASE ====================

mongo_url = os.environ.get(
    "MONGO_URL",
    "mongodb+srv://dsetuser:DSETUSERPASS@cluster0.ifzbchw.mongodb.net/dset"
)
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get("DB_NAME", "dset")]

# ==================== APP ====================

app = FastAPI(title="DSET Cybersecurity Platform API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== AUTH ====================

JWT_SECRET = os.environ.get("JWT_SECRET", "dset-secret")
JWT_ALGORITHM = "HS256"

def create_token(user: dict):
    payload = {
        "sub": user["id"],
        "name": user["name"],
        "exp": datetime.now(timezone.utc).timestamp() + 86400
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401)
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401)
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401)
    return user

# ==================== MODELS ====================

class UserLogin(BaseModel):
    id: str
    mobile: str

class UserResponse(BaseModel):
    id: str
    name: str
    mobile: str

class TokenResponse(BaseModel):
    token: str
    user: UserResponse

# ==================== HELPERS ====================

def normalize_mobile(mobile: str):
    digits = "".join(filter(str.isdigit, str(mobile)))
    if digits.startswith("880"):
        digits = digits[3:]
    if len(digits) == 10:
        digits = "0" + digits
    return digits

# ==================== ENDPOINTS ====================

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    user = await db.users.find_one({"id": data.id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if normalize_mobile(user["mobile"]) != normalize_mobile(data.mobile):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return TokenResponse(
        token=token,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            mobile=user["mobile"]
        )
    )

@api_router.get("/modules/{module_id}")
async def get_module(module_id: int):
    file = ROOT_DIR / "modules" / f"module{module_id}.html"
    if not file.exists():
        raise HTTPException(status_code=404)
    return FileResponse(file, media_type="text/html")

@api_router.get("/health")
async def health():
    return {"status": "ok"}

app.include_router(api_router)

@app.on_event("startup")
async def startup():
    await db.users.create_index("id", unique=True)

