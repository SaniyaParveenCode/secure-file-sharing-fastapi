from fastapi import FastAPI, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from typing import List
import os
import shutil

app = FastAPI()

# In-memory stores for demo purposes
USERS_DB = {}
FILES_DB = []

SECRET_KEY = "super-secret-key"
serializer = URLSafeTimedSerializer(SECRET_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- Models ----------------
class User(BaseModel):
    email: EmailStr
    password: str
    role: str  # 'ops' or 'client'
    is_verified: bool = False

class FileMeta(BaseModel):
    id: int
    filename: str
    uploaded_by: str

# ---------------- Helpers ----------------
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = USERS_DB.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# ---------------- Auth Routes ----------------
@app.post("/signup")
def signup(user: User):
    if user.email in USERS_DB:
        raise HTTPException(status_code=400, detail="User exists")
    USERS_DB[user.email] = user
    token = serializer.dumps(user.email, salt="email-verify")
    return {"verify_url": f"/verify-email?token={token}"}

@app.get("/verify-email")
def verify_email(token: str):
    try:
        email = serializer.loads(token, salt="email-verify", max_age=3600)
        if email in USERS_DB:
            USERS_DB[email].is_verified = True
            return {"message": "Email verified"}
        raise HTTPException(status_code=404, detail="User not found")
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="Token expired")
    except BadSignature:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = USERS_DB.get(form.username)
    if not user or user.password != form.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": user.email, "token_type": "bearer"}

# ---------------- Ops Routes ----------------
@app.post("/upload-file")
def upload_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    if current_user.role != "ops":
        raise HTTPException(status_code=403, detail="Unauthorized")
    if not file.filename.endswith((".pptx", ".docx", ".xlsx")):
        raise HTTPException(status_code=400, detail="Invalid file type")

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    file_meta = FileMeta(id=len(FILES_DB) + 1, filename=file.filename, uploaded_by=current_user.email)
    FILES_DB.append(file_meta)
    return {"message": "File uploaded successfully"}

# ---------------- Client Routes ----------------
@app.get("/files", response_model=List[FileMeta])
def list_files(current_user: User = Depends(get_current_user)):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Only clients can view files")
    return FILES_DB

@app.get("/download-file/{file_id}")
def generate_download_link(file_id: int, current_user: User = Depends(get_current_user)):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Only clients can download")
    token = serializer.dumps({"file_id": file_id, "user": current_user.email}, salt="file-download")
    return {"download_link": f"/secure-download/{token}", "message": "success"}

@app.get("/secure-download/{token}")
def secure_download(token: str, current_user: User = Depends(get_current_user)):
    try:
        data = serializer.loads(token, salt="file-download", max_age=300)
        if current_user.role != "client" or current_user.email != data["user"]:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        file_id = data["file_id"]
        for f in FILES_DB:
            if f.id == file_id:
                return {"file": f.filename, "message": "Download allowed (mock)"}
        raise HTTPException(status_code=404, detail="File not found")

    except SignatureExpired:
        raise HTTPException(status_code=400, detail="Token expired")
    except BadSignature:
        raise HTTPException(status_code=400, detail="Invalid token")

