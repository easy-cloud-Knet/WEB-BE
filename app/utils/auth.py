from pathlib import Path
from passlib.context import CryptContext
import smtplib
import random
import string
from string import Template
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.utils.database.web_backend.models import VerificationCode
import os
from dotenv import load_dotenv
from urllib.parse import unquote
import logging

logging.basicConfig(level=logging.INFO)

# .env 파일에서 환경 변수 로드
load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "utils" / "verification.html"

def render_email_template(email: str, code: str) -> str:
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    return Template(html).safe_substitute(email=email, code=code)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# 인증 코드 생성 함수
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

# 인증 코드 저장 (DB 사용)
def save_verification_code(email: str, db: Session):
    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # 기존 코드 삭제 후 새로운 코드 저장
    db.query(VerificationCode).filter(VerificationCode.email == email).delete()
    
    new_code = VerificationCode(email=email, code=code, expires_at=expires_at)
    db.add(new_code)
    db.commit()
    return code

# 이메일 전송 함수
def send_verification_email(email: str, db: Session):
    logging.info(f"Encoded email received: {email}")
    code = save_verification_code(email, db)
    subject = "Verification Code"
    
    # HTML 본문 (사용자가 제공한 템플릿)
    body = render_email_template(email=email, code=code)
    
    msg = MIMEMultipart("alternative")
    msg['From'] = SENDER_EMAIL
    msg['To'] = email
    msg['Subject'] = subject
    
    # fallback plain text
    plain_text = f"Your verification code is: {code}. It expires in 5 minutes."
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(body, "html"))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.quit()
        logging.info("Verification email sent successfully")
        return {"msg": "Verification email sent successfully"}
    except Exception as e:
        logging.info(f"Failed sending verification email: {e}")
        return {"error": str(e)}


# 인증 코드 검증 함수
def verify_code(email: str, code: str, db: Session) -> bool:
    stored_code = db.query(VerificationCode).filter(
        VerificationCode.email == email,
        VerificationCode.expires_at > datetime.utcnow()
    ).first()

    if stored_code and stored_code.code == code:
        db.delete(stored_code)  # 검증 완료 후 코드 삭제
        db.commit()
        return True
    return False
