from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import hashlib
import pandas as pd
from io import BytesIO

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'dset_database')]

# JWT Secret
JWT_SECRET = os.environ.get('JWT_SECRET', 'dset-cyber-security-2025-secret-key')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 168  # 7 days

# Admin credentials (can be moved to env/database in production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'ADMIN')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '12345678')
ADMIN_CREDENTIALS = {
    ADMIN_USERNAME: ADMIN_PASSWORD
}

# OpenAI for chatbot (optional - will work without it)
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')

# Create the main app
app = FastAPI(title="DSET Cybersecurity Platform API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str
    mobile: str
    role: str = "student"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserLogin(BaseModel):
    user_id: str
    mobile: str

class AdminLogin(BaseModel):
    user_id: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    name: str
    mobile: str
    role: str
    quiz_progress: Optional[Dict[str, Any]] = None
    certificate_earned: bool = False

class TokenResponse(BaseModel):
    token: str
    user: UserResponse

class QuizProgress(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    current_quiz: int = 1
    max_unlocked: int = 1
    completed_quizzes: List[int] = []
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class QuizAttempt(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    quiz_id: int
    answers: Dict[str, Any] = {}
    correct_count: int = 0
    wrong_count: int = 0
    total_questions: int = 0
    score_percentage: float = 0.0
    completed: bool = False
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

class QuizAnswerSave(BaseModel):
    quiz_id: int
    question_index: int
    selected_answer: str
    is_correct: bool

class QuizComplete(BaseModel):
    quiz_id: int
    correct_count: int
    wrong_count: int
    total_questions: int
    score_percentage: float

class Certificate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    certificate_number: str = Field(default_factory=lambda: f"DSET-{uuid.uuid4().hex[:8].upper()}")
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    download_count: int = 0
    last_downloaded: Optional[datetime] = None

class LoginLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    role: str = "student"
    login_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    device_info: Optional[str] = None
    ip_address: Optional[str] = None

class ActivityLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    activity_type: str  # login, quiz_start, quiz_complete, certificate_generate, certificate_download
    details: Dict[str, Any] = {}
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str

# ==================== AUTH HELPERS ====================

def create_token(user_data: dict, is_admin: bool = False) -> str:
    payload = {
        "sub": user_data["user_id"],
        "name": user_data["name"],
        "role": user_data.get("role", "student"),
        "is_admin": is_admin,
        "exp": datetime.now(timezone.utc).timestamp() + (JWT_EXPIRATION_HOURS * 3600)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = await db.users.find_one({"user_id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Add is_admin flag from token
    user["is_admin"] = payload.get("is_admin", False)
    return user

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Require admin role"""
    user = await get_current_user(credentials)
    if user.get("role") != "admin" and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def normalize_mobile(mobile: str) -> str:
    """Normalize mobile number to 11-digit Bangladesh format"""
    digits = ''.join(filter(str.isdigit, str(mobile)))
    if digits.startswith('880'):
        digits = digits[3:]
    if len(digits) == 10 and digits.startswith('1'):
        digits = '0' + digits
    return digits

async def log_activity(user_id: str, user_name: str, activity_type: str, details: dict = None):
    """Log user activity for monitoring"""
    activity = ActivityLog(
        user_id=user_id,
        user_name=user_name,
        activity_type=activity_type,
        details=details or {}
    )
    activity_dict = activity.model_dump()
    activity_dict['timestamp'] = activity_dict['timestamp'].isoformat()
    await db.activity_logs.insert_one(activity_dict)

# ==================== AUTH ENDPOINTS ====================

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(login_data: UserLogin, request: Request):
    """Login with user ID and mobile number (for students)"""
    normalized_mobile = normalize_mobile(login_data.mobile)
    
    user = await db.users.find_one({
        "user_id": login_data.user_id.strip()
    }, {"_id": 0})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_mobile = normalize_mobile(user.get("mobile", ""))
    if user_mobile != normalized_mobile:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Log the login
    login_log = LoginLog(
        user_id=user["user_id"],
        user_name=user["name"],
        role=user.get("role", "student"),
        ip_address=client_ip,
        device_info=user_agent[:200]  # Truncate long user agents
    )
    login_dict = login_log.model_dump()
    login_dict['login_at'] = login_dict['login_at'].isoformat()
    await db.login_logs.insert_one(login_dict)
    
    # Log activity
    await log_activity(user["user_id"], user["name"], "login", {
        "ip": client_ip,
        "device": user_agent[:100]
    })
    
    # Get quiz progress
    progress = await db.quiz_progress.find_one({"user_id": user["user_id"]}, {"_id": 0})
    
    # Check if certificate earned
    cert = await db.certificates.find_one({"user_id": user["user_id"]}, {"_id": 0})
    
    token = create_token(user)
    
    return TokenResponse(
        token=token,
        user=UserResponse(
            id=user["id"],
            user_id=user["user_id"],
            name=user["name"],
            mobile=user["mobile"],
            role=user.get("role", "student"),
            quiz_progress=progress,
            certificate_earned=cert is not None
        )
    )

@api_router.post("/auth/admin-login", response_model=TokenResponse)
async def admin_login(login_data: AdminLogin, request: Request):
    """Login with user ID and password (for admin)"""
    user_id = login_data.user_id.strip().upper()
    password = login_data.password
    
    # Check admin credentials
    if user_id not in ADMIN_CREDENTIALS or ADMIN_CREDENTIALS[user_id] != password:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    # Get or create admin user in database
    admin_user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    
    if not admin_user:
        # Create admin user
        admin_user = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "name": "Administrator",
            "mobile": "N/A",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(admin_user)
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Log admin login
    login_log = LoginLog(
        user_id=user_id,
        user_name="Administrator",
        role="admin",
        ip_address=client_ip,
        device_info=user_agent[:200]
    )
    login_dict = login_log.model_dump()
    login_dict['login_at'] = login_dict['login_at'].isoformat()
    await db.login_logs.insert_one(login_dict)
    
    await log_activity(user_id, "Administrator", "admin_login", {"ip": client_ip})
    
    token = create_token(admin_user, is_admin=True)
    
    return TokenResponse(
        token=token,
        user=UserResponse(
            id=admin_user["id"],
            user_id=admin_user["user_id"],
            name=admin_user["name"],
            mobile=admin_user.get("mobile", "N/A"),
            role="admin",
            quiz_progress=None,
            certificate_earned=False
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    progress = await db.quiz_progress.find_one({"user_id": current_user["user_id"]}, {"_id": 0})
    cert = await db.certificates.find_one({"user_id": current_user["user_id"]}, {"_id": 0})
    
    return UserResponse(
        id=current_user["id"],
        user_id=current_user["user_id"],
        name=current_user["name"],
        mobile=current_user.get("mobile", "N/A"),
        role=current_user.get("role", "student"),
        quiz_progress=progress,
        certificate_earned=cert is not None
    )

@api_router.post("/auth/verify")
async def verify_auth(current_user: dict = Depends(get_current_user)):
    """Verify if token is still valid"""
    return {"valid": True, "user_id": current_user["user_id"], "role": current_user.get("role")}

# ==================== USER MANAGEMENT ====================

@api_router.post("/users/import-excel")
async def import_users_from_excel(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_admin_user)
):
    """Import users from Excel file (Admin only)"""
    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="File must be an Excel file (.xlsx or .xls)")
    
    contents = await file.read()
    df = pd.read_excel(BytesIO(contents))
    
    imported_count = 0
    updated_count = 0
    
    for _, row in df.iterrows():
        user_id = str(row.get('ID', '')).strip()
        name = str(row.get('Name', '')).strip()
        mobile = str(row.get('Mobile', '')).strip()
        
        if not user_id or not name or not mobile:
            continue
        
        # Clean mobile number
        if mobile.endswith('.0'):
            mobile = mobile[:-2]
        
        existing = await db.users.find_one({"user_id": user_id})
        
        if existing:
            await db.users.update_one(
                {"user_id": user_id},
                {"$set": {"name": name, "mobile": mobile}}
            )
            updated_count += 1
        else:
            user = UserBase(
                user_id=user_id,
                name=name,
                mobile=mobile
            )
            user_dict = user.model_dump()
            user_dict['created_at'] = user_dict['created_at'].isoformat()
            await db.users.insert_one(user_dict)
            imported_count += 1
    
    await log_activity(
        current_user["user_id"], 
        current_user["name"], 
        "import_users",
        {"imported": imported_count, "updated": updated_count, "filename": file.filename}
    )
    
    return {
        "message": "Import completed",
        "imported": imported_count,
        "updated": updated_count,
        "total": imported_count + updated_count
    }

@api_router.get("/users/list")
async def list_users(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    has_certificate: Optional[bool] = None,
    current_user: dict = Depends(get_admin_user)
):
    """List all users with their progress (Admin only)"""
    query = {"role": {"$ne": "admin"}}  # Exclude admin users
    
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"user_id": {"$regex": search, "$options": "i"}}
        ]
    
    skip = (page - 1) * limit
    users = await db.users.find(query, {"_id": 0}).skip(skip).limit(limit).to_list(limit)
    total = await db.users.count_documents(query)
    
    # Enrich with progress and certificate data
    enriched_users = []
    for user in users:
        progress = await db.quiz_progress.find_one({"user_id": user["user_id"]}, {"_id": 0})
        cert = await db.certificates.find_one({"user_id": user["user_id"]}, {"_id": 0})
        
        # Get last login
        last_login = await db.login_logs.find_one(
            {"user_id": user["user_id"]},
            {"_id": 0}
        )
        if last_login:
            last_login = await db.login_logs.find(
                {"user_id": user["user_id"]},
                {"_id": 0}
            ).sort("login_at", -1).limit(1).to_list(1)
            last_login = last_login[0] if last_login else None
        
        user_data = {
            **user,
            "quiz_progress": progress,
            "certificate": cert,
            "has_certificate": cert is not None,
            "completed_quizzes": len(progress.get("completed_quizzes", [])) if progress else 0,
            "last_login": last_login.get("login_at") if last_login else None
        }
        
        # Filter by certificate if specified
        if has_certificate is not None:
            if has_certificate and cert:
                enriched_users.append(user_data)
            elif not has_certificate and not cert:
                enriched_users.append(user_data)
        else:
            enriched_users.append(user_data)
    
    return {
        "users": enriched_users,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/users/{user_id}/details")
async def get_user_details(
    user_id: str,
    current_user: dict = Depends(get_admin_user)
):
    """Get detailed info about a specific user (Admin only)"""
    user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get all related data
    progress = await db.quiz_progress.find_one({"user_id": user_id}, {"_id": 0})
    cert = await db.certificates.find_one({"user_id": user_id}, {"_id": 0})
    
    # Get all quiz attempts
    attempts = await db.quiz_attempts.find(
        {"user_id": user_id},
        {"_id": 0}
    ).sort("started_at", -1).to_list(100)
    
    # Get login history
    logins = await db.login_logs.find(
        {"user_id": user_id},
        {"_id": 0}
    ).sort("login_at", -1).limit(20).to_list(20)
    
    # Get activity logs
    activities = await db.activity_logs.find(
        {"user_id": user_id},
        {"_id": 0}
    ).sort("timestamp", -1).limit(50).to_list(50)
    
    return {
        "user": user,
        "quiz_progress": progress,
        "certificate": cert,
        "quiz_attempts": attempts,
        "login_history": logins,
        "activity_logs": activities
    }

# ==================== QUIZ PROGRESS ====================

@api_router.get("/quiz/progress")
async def get_quiz_progress(current_user: dict = Depends(get_current_user)):
    """Get current user's quiz progress"""
    progress = await db.quiz_progress.find_one(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    )
    
    if not progress:
        # Create initial progress
        progress = QuizProgress(user_id=current_user["user_id"]).model_dump()
        progress['updated_at'] = progress['updated_at'].isoformat()
        await db.quiz_progress.insert_one(progress)
        progress.pop('_id', None)
    else:
        if isinstance(progress.get('updated_at'), str):
            pass
        elif progress.get('updated_at'):
            progress['updated_at'] = progress['updated_at'].isoformat()
        progress.pop('_id', None)
    
    return progress

@api_router.post("/quiz/save-answer")
async def save_quiz_answer(
    answer_data: QuizAnswerSave,
    current_user: dict = Depends(get_current_user)
):
    """Save a single answer in real-time"""
    user_id = current_user["user_id"]
    quiz_id = answer_data.quiz_id
    
    # Find or create current attempt
    attempt = await db.quiz_attempts.find_one({
        "user_id": user_id,
        "quiz_id": quiz_id,
        "completed": False
    }, {"_id": 0})
    
    if not attempt:
        attempt = QuizAttempt(user_id=user_id, quiz_id=quiz_id).model_dump()
        attempt['started_at'] = attempt['started_at'].isoformat()
        await db.quiz_attempts.insert_one(attempt)
        
        # Log quiz start
        await log_activity(user_id, current_user["name"], "quiz_start", {"quiz_id": quiz_id})
    
    # Update the answer
    answer_key = f"q{answer_data.question_index}"
    update_data = {
        f"answers.{answer_key}": {
            "selected": answer_data.selected_answer,
            "is_correct": answer_data.is_correct,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }
    }
    
    await db.quiz_attempts.update_one(
        {"id": attempt["id"]},
        {"$set": update_data}
    )
    
    return {"saved": True, "question": answer_data.question_index}

@api_router.post("/quiz/complete")
async def complete_quiz(
    quiz_data: QuizComplete,
    current_user: dict = Depends(get_current_user)
):
    """Mark a quiz as completed and update progress"""
    user_id = current_user["user_id"]
    quiz_id = quiz_data.quiz_id
    
    completed_at = datetime.now(timezone.utc).isoformat()
    
    await db.quiz_attempts.update_one(
        {"user_id": user_id, "quiz_id": quiz_id, "completed": False},
        {
            "$set": {
                "completed": True,
                "completed_at": completed_at,
                "correct_count": quiz_data.correct_count,
                "wrong_count": quiz_data.wrong_count,
                "total_questions": quiz_data.total_questions,
                "score_percentage": quiz_data.score_percentage
            }
        },
        upsert=True
    )
    
    # Update quiz progress
    progress = await db.quiz_progress.find_one({"user_id": user_id}, {"_id": 0})
    
    if not progress:
        progress = QuizProgress(user_id=user_id).model_dump()
    
    completed_quizzes = progress.get("completed_quizzes", [])
    if quiz_id not in completed_quizzes:
        completed_quizzes.append(quiz_id)
    
    next_quiz = quiz_id + 1 if quiz_id < 5 else 5
    max_unlocked = max(progress.get("max_unlocked", 1), next_quiz)
    
    await db.quiz_progress.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "completed_quizzes": completed_quizzes,
                "max_unlocked": max_unlocked,
                "current_quiz": next_quiz,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        },
        upsert=True
    )
    
    # Log activity
    await log_activity(user_id, current_user["name"], "quiz_complete", {
        "quiz_id": quiz_id,
        "score": quiz_data.score_percentage,
        "correct": quiz_data.correct_count,
        "wrong": quiz_data.wrong_count
    })
    
    all_completed = len(set(completed_quizzes)) >= 5
    
    return {
        "completed": True,
        "quiz_id": quiz_id,
        "next_quiz": next_quiz,
        "max_unlocked": max_unlocked,
        "all_quizzes_completed": all_completed,
        "can_get_certificate": all_completed
    }

@api_router.get("/quiz/attempts")
async def get_quiz_attempts(
    quiz_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get user's quiz attempts"""
    query = {"user_id": current_user["user_id"]}
    if quiz_id:
        query["quiz_id"] = quiz_id
    
    attempts = await db.quiz_attempts.find(query, {"_id": 0}).to_list(100)
    return {"attempts": attempts}

# ==================== CERTIFICATE ====================

@api_router.get("/certificate/check")
async def check_certificate_eligibility(current_user: dict = Depends(get_current_user)):
    """Check if user is eligible for certificate"""
    progress = await db.quiz_progress.find_one(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    )
    
    if not progress:
        return {"eligible": False, "reason": "No quiz progress found", "completed_count": 0}
    
    completed = set(progress.get("completed_quizzes", []))
    required = {1, 2, 3, 4, 5}
    
    if not required.issubset(completed):
        missing = required - completed
        return {
            "eligible": False,
            "reason": f"Missing quizzes: {sorted(missing)}",
            "completed_count": len(completed),
            "required": 5
        }
    
    cert = await db.certificates.find_one(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    )
    
    return {
        "eligible": True,
        "completed_count": len(completed),
        "required": 5,
        "certificate": cert
    }

@api_router.post("/certificate/generate")
async def generate_certificate(current_user: dict = Depends(get_current_user)):
    """Generate a certificate for the user"""
    progress = await db.quiz_progress.find_one(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    )
    
    if not progress:
        raise HTTPException(status_code=400, detail="No quiz progress found")
    
    completed = set(progress.get("completed_quizzes", []))
    required = {1, 2, 3, 4, 5}
    
    if not required.issubset(completed):
        raise HTTPException(status_code=400, detail="Must complete all 5 quizzes first")
    
    existing_cert = await db.certificates.find_one(
        {"user_id": current_user["user_id"]},
        {"_id": 0}
    )
    
    if existing_cert:
        await db.certificates.update_one(
            {"user_id": current_user["user_id"]},
            {
                "$inc": {"download_count": 1},
                "$set": {"last_downloaded": datetime.now(timezone.utc).isoformat()}
            }
        )
        existing_cert["download_count"] += 1
        
        await log_activity(current_user["user_id"], current_user["name"], "certificate_download", {
            "certificate_number": existing_cert["certificate_number"]
        })
        
        return existing_cert
    
    cert = Certificate(
        user_id=current_user["user_id"],
        user_name=current_user["name"]
    )
    cert_dict = cert.model_dump()
    cert_dict['issued_at'] = cert_dict['issued_at'].isoformat()
    
    await db.certificates.insert_one(cert_dict)
    
    await log_activity(current_user["user_id"], current_user["name"], "certificate_generate", {
        "certificate_number": cert_dict["certificate_number"]
    })
    
    return cert_dict

@api_router.post("/certificate/download")
async def record_certificate_download(current_user: dict = Depends(get_current_user)):
    """Record a certificate download"""
    cert = await db.certificates.find_one({"user_id": current_user["user_id"]}, {"_id": 0})
    
    if cert:
        await db.certificates.update_one(
            {"user_id": current_user["user_id"]},
            {
                "$inc": {"download_count": 1},
                "$set": {"last_downloaded": datetime.now(timezone.utc).isoformat()}
            }
        )
        
        await log_activity(current_user["user_id"], current_user["name"], "certificate_download", {
            "certificate_number": cert["certificate_number"]
        })
    
    return {"recorded": True}

# ==================== AI CHATBOT (OpenAI Based - Optional) ====================

@api_router.post("/chat", response_model=ChatResponse)
async def chat_with_bot(
    chat_data: ChatMessage,
    current_user: dict = Depends(get_current_user)
):
    """Chat with AI guide bot - Uses OpenAI API if configured"""
    session_id = chat_data.session_id or f"{current_user['user_id']}-{uuid.uuid4().hex[:8]}"
    
    system_message = """You are CYPHER, an AI guide for the DSET (Defense Security Education Training) cybersecurity platform. 
    
You help students with:
1. Navigation - How to use the platform, find courses, take quizzes
2. Cybersecurity Topics - Basic concepts, terminology, best practices
3. Quiz Help - Explaining quiz topics (but NOT giving answers)
4. Certificate Info - How to earn and download certificates
5. General Support - Any questions about the platform

Platform Structure:
- 4 Learning Modules: Fundamentals, Cyber Attack, Cyber Defense, In Action
- 5 Quizzes: One per module + Final Certification Exam
- Quizzes unlock sequentially (must complete quiz 1 before quiz 2, etc.)
- Certificate requires completing ALL 5 quizzes

Be friendly, helpful, and use cybersecurity themed language. Keep responses concise but informative.
Format responses with markdown when helpful."""

    try:
        if not OPENAI_API_KEY:
            # Fallback response when OpenAI is not configured
            return ChatResponse(
                response="I'm CYPHER, your cybersecurity guide! The AI chat feature requires OpenAI API configuration. For now, here's what I can tell you:\n\n**Platform Overview:**\n- Complete 4 learning modules\n- Pass 5 quizzes sequentially\n- Earn your certificate!\n\nNeed help? Check the learning modules or contact your administrator.",
                session_id=session_id
            )
        
        # Use OpenAI API
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": chat_data.message}
            ],
            max_tokens=500
        )
        
        ai_response = response.choices[0].message.content
        
        # Store chat session
        await db.chat_sessions.update_one(
            {"session_id": session_id, "user_id": current_user["user_id"]},
            {
                "$push": {
                    "messages": {
                        "role": "user",
                        "content": chat_data.message,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                },
                "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}
            },
            upsert=True
        )
        
        await db.chat_sessions.update_one(
            {"session_id": session_id},
            {
                "$push": {
                    "messages": {
                        "role": "assistant",
                        "content": ai_response,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            }
        )
        
        return ChatResponse(response=ai_response, session_id=session_id)
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return ChatResponse(
            response="I encountered an error. Please try again or rephrase your question.",
            session_id=session_id
        )

# ==================== ADMIN DASHBOARD ENDPOINTS ====================

@api_router.get("/admin/stats")
async def get_admin_stats(current_user: dict = Depends(get_admin_user)):
    """Get comprehensive platform statistics (Admin only)"""
    total_users = await db.users.count_documents({"role": {"$ne": "admin"}})
    total_logins = await db.login_logs.count_documents({})
    total_certificates = await db.certificates.count_documents({})
    
    # Users who completed at least one quiz
    users_with_progress = await db.quiz_progress.count_documents({"completed_quizzes.0": {"$exists": True}})
    
    # Users who completed all quizzes
    all_quizzes_completed = await db.quiz_progress.count_documents({
        "completed_quizzes": {"$all": [1, 2, 3, 4, 5]}
    })
    
    # Quiz completion stats
    quiz_stats = []
    for quiz_id in range(1, 6):
        completed = await db.quiz_attempts.count_documents({"quiz_id": quiz_id, "completed": True})
        quiz_stats.append({"quiz_id": quiz_id, "completions": completed})
    
    # Logins today
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    logins_today = await db.login_logs.count_documents({
        "login_at": {"$gte": today_start.isoformat()}
    })
    
    # Certificates issued today
    certs_today = await db.certificates.count_documents({
        "issued_at": {"$gte": today_start.isoformat()}
    })
    
    # Active users (logged in within last 7 days)
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    active_users_pipeline = [
        {"$match": {"login_at": {"$gte": week_ago}}},
        {"$group": {"_id": "$user_id"}},
        {"$count": "count"}
    ]
    active_result = await db.login_logs.aggregate(active_users_pipeline).to_list(1)
    active_users = active_result[0]["count"] if active_result else 0
    
    return {
        "total_users": total_users,
        "total_logins": total_logins,
        "total_certificates": total_certificates,
        "users_with_progress": users_with_progress,
        "all_quizzes_completed": all_quizzes_completed,
        "quiz_stats": quiz_stats,
        "logins_today": logins_today,
        "certificates_today": certs_today,
        "active_users_week": active_users,
        "certificate_rate": round((total_certificates / total_users * 100), 2) if total_users > 0 else 0
    }

@api_router.get("/admin/recent-activity")
async def get_recent_activity(
    limit: int = 50,
    activity_type: Optional[str] = None,
    current_user: dict = Depends(get_admin_user)
):
    """Get recent platform activity (Admin only)"""
    query = {}
    if activity_type:
        query["activity_type"] = activity_type
    
    activities = await db.activity_logs.find(
        query,
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return {"activities": activities}

@api_router.get("/admin/login-logs")
async def get_login_logs(
    page: int = 1,
    limit: int = 50,
    user_id: Optional[str] = None,
    current_user: dict = Depends(get_admin_user)
):
    """Get login logs sorted by most recent first (Admin only)"""
    query = {}
    if user_id:
        query["user_id"] = user_id
    
    skip = (page - 1) * limit
    
    # Sort by login_at descending (most recent first)
    logs = await db.login_logs.find(
        query,
        {"_id": 0}
    ).sort("login_at", -1).skip(skip).limit(limit).to_list(limit)
    
    total = await db.login_logs.count_documents(query)
    
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.delete("/admin/login-logs/clear")
async def clear_login_logs(current_user: dict = Depends(get_admin_user)):
    """Clear all login logs (Admin only)"""
    result = await db.login_logs.delete_many({})
    
    await log_activity(
        current_user["user_id"],
        current_user["name"],
        "clear_login_logs",
        {"deleted_count": result.deleted_count}
    )
    
    return {"message": "Login logs cleared", "deleted_count": result.deleted_count}

@api_router.get("/admin/certificates")
async def get_all_certificates(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    current_user: dict = Depends(get_admin_user)
):
    """Get all certificates (Admin only)"""
    query = {}
    if search:
        query["$or"] = [
            {"user_name": {"$regex": search, "$options": "i"}},
            {"user_id": {"$regex": search, "$options": "i"}},
            {"certificate_number": {"$regex": search, "$options": "i"}}
        ]
    
    skip = (page - 1) * limit
    certs = await db.certificates.find(
        query,
        {"_id": 0}
    ).sort("issued_at", -1).skip(skip).limit(limit).to_list(limit)
    
    total = await db.certificates.count_documents(query)
    
    return {
        "certificates": certs,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/admin/quiz-analytics")
async def get_quiz_analytics(current_user: dict = Depends(get_admin_user)):
    """Get detailed quiz analytics (Admin only)"""
    analytics = []
    
    for quiz_id in range(1, 6):
        attempts = await db.quiz_attempts.find(
            {"quiz_id": quiz_id, "completed": True},
            {"_id": 0, "score_percentage": 1, "correct_count": 1, "wrong_count": 1}
        ).to_list(10000)
        
        if attempts:
            scores = [a["score_percentage"] for a in attempts]
            avg_score = sum(scores) / len(scores)
            pass_rate = len([s for s in scores if s >= 60]) / len(scores) * 100
        else:
            avg_score = 0
            pass_rate = 0
        
        analytics.append({
            "quiz_id": quiz_id,
            "total_attempts": len(attempts),
            "average_score": round(avg_score, 2),
            "pass_rate": round(pass_rate, 2)
        })
    
    return {"quiz_analytics": analytics}

@api_router.get("/admin/user-progress-summary")
async def get_user_progress_summary(current_user: dict = Depends(get_admin_user)):
    """Get summary of user progress distribution (Admin only)"""
    # Count users by quiz completion level
    progress_distribution = []
    
    for level in range(6):  # 0 to 5 quizzes completed
        if level == 0:
            # Users with no progress
            total_users = await db.users.count_documents({"role": {"$ne": "admin"}})
            users_with_any_progress = await db.quiz_progress.count_documents({
                "completed_quizzes.0": {"$exists": True}
            })
            count = total_users - users_with_any_progress
        else:
            count = await db.quiz_progress.count_documents({
                f"completed_quizzes.{level-1}": {"$exists": True},
                f"completed_quizzes.{level}": {"$exists": False}
            }) if level < 5 else await db.quiz_progress.count_documents({
                "completed_quizzes": {"$size": 5}
            })
        
        progress_distribution.append({
            "quizzes_completed": level,
            "user_count": count
        })
    
    return {"progress_distribution": progress_distribution}

# ==================== MODULES ENDPOINTS ====================

@api_router.get("/modules/{module_id}")
async def get_module_content(module_id: int):
    """Get module HTML content"""
    modules_dir = ROOT_DIR / "modules"
    module_file = modules_dir / f"module{module_id}.html"
    
    if not module_file.exists():
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")
    
    return FileResponse(module_file, media_type="text/html")

@api_router.get("/modules")
async def list_modules():
    """List all available modules"""
    return {
        "modules": [
            {"id": 1, "title": "Cybersecurity Fundamentals", "description": "Introduction to cybersecurity concepts"},
            {"id": 2, "title": "Cyber Attack", "description": "Understanding cyber threats and attack vectors"},
            {"id": 3, "title": "Cyber Defense", "description": "Defense strategies and security measures"},
            {"id": 4, "title": "In Action", "description": "Real-world cybersecurity applications"}
        ]
    }

# ==================== BASIC ENDPOINTS ====================

@api_router.get("/")
async def root():
    return {"message": "DSET Cybersecurity Platform API", "version": "2.0.0"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize database indexes"""
    await db.users.create_index("user_id", unique=True)
    await db.quiz_progress.create_index("user_id", unique=True)
    await db.quiz_attempts.create_index([("user_id", 1), ("quiz_id", 1)])
    await db.certificates.create_index("user_id", unique=True)
    await db.certificates.create_index("certificate_number", unique=True)
    await db.login_logs.create_index("login_at")
    await db.login_logs.create_index("user_id")
    await db.activity_logs.create_index("timestamp")
    await db.activity_logs.create_index("user_id")
    await db.activity_logs.create_index("activity_type")
    await db.chat_sessions.create_index("session_id")
    logger.info("Database indexes created")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
