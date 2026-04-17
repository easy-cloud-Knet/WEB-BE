from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.utils.auth import get_password_hash, verify_password, send_verification_email, verify_code
from app.utils.verification import (
    create_access_token, create_refresh_token, decode_refresh_token, get_current_user
)
from app.utils.database.web_backend.database import get_db
from app.utils.database.web_backend.models import User
import uuid
from pydantic import BaseModel

router = APIRouter()

class basic_info(BaseModel):
    username: str
    email: str

class register_info(basic_info):
    password: str

class email(BaseModel):
    email: str

class email_with_purpose(email):
    purpose: str

class info_with_code(basic_info):
    code: str

class email_with_code(email):
    code: str

class change_password_info(info_with_code):
    new_password: str

class no_name_info(email):
    password: str

@router.post("/login")
async def login(data: no_name_info, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not verify_password(data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")
    
    access_token = create_access_token(payload={"user_id": user.id})
    refresh_token = create_refresh_token(payload={"user_id": user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }

# 회원가입 API
@router.post("/register")
async def register_user(data: register_info, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(data.password)
    existing_user = db.query(User).filter((User.username == data.username) | (User.email == data.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    new_user = User(
        id=str(uuid.uuid4()),
        username=data.username,
        email=data.email,
        password=hashed_password
    )
    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="User registration failed")

    return {"msg": "User registered successfully", "id": new_user.id}

# 이메일 전송
@router.post("/send-email")
async def send_email(data: email, db: Session = Depends(get_db)):
    send_verification_email(data.email, db)
    return {"msg": f"Verification email sent for {data.email}"}

# 인증번호 확인 API
@router.post("/verify-code")
async def verify_code_api(data: email_with_code, db: Session = Depends(get_db)):
    if not verify_code(data.email, data.code, db):
        raise HTTPException(status_code=400, detail="Invalid verification code")
    return {"msg": "Verification successful"}

# 비밀번호 변경 (이메일 인증 추가됨)
@router.post("/change-password")
async def change_password(
    data: change_password_info,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):

    user = db.query(User).filter(User.id == current_user, User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")  

    # 이메일 인증 코드 확인
    if data.code:
        if not verify_code(data.email, data.code, db):
            raise HTTPException(status_code=400, detail="Invalid verification code")

    # 새 비밀번호 설정
    user.password = get_password_hash(data.new_password)
    db.commit()
    
    return {"msg": "Password changed successfully"}

# 비밀번호 재설정 (이메일 인증 필요)
@router.post("/reset-password")
async def reset_password(data: info_with_code, db: Session = Depends(get_db)):
    if not verify_code(data.email, data.code):
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.password = get_password_hash(data.password)
    db.commit()
    return {"msg": "Password reset successfully"}

# Access Token 재발급 API
@router.post("/refresh-access-token")
async def refresh_access_token(refresh_token: str):
    payload = decode_refresh_token(refresh_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid refresh token")
    
    new_access_token = create_access_token(payload={"user_id": user_id})
    return {"access_token": new_access_token, "token_type": "bearer"}

# Refresh Token 재발급 API
@router.post("/refresh-token")
async def refresh_refresh_token(refresh_token: str):
    payload = decode_refresh_token(refresh_token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid refresh token")
    
    new_refresh_token = create_refresh_token(payload={"user_id": user_id})
    return {"refresh_token": new_refresh_token, "token_type": "bearer"}
