from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.utils.verification import get_current_user
from app.utils.auth import send_verification_email, verify_code
from app.utils.database.web_backend.database import get_db as get_db_web
from app.utils.database.web_backend.models import VMs, User, VmSharedUsers, VmAdminChangeRequest
from app.utils.database.control_to_backend.database import get_db as get_db_con2web
from app.utils.database.control_to_backend.models import InstanceTypes, OsList
import uuid
import redis
from pydantic import BaseModel
from typing import List
import requests, json
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 환경 변수에서 Redis 정보 가져오기
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_URL = f"http://{REDIS_HOST}:{REDIS_PORT}" 
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# Redis 연결 설정
redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    #password=REDIS_PASSWORD,
    db=0,
    decode_responses=True
)

# 환경 변수에서 Control 정보 가져오기
CONTROL_HOST = os.getenv("CONTROL_HOST")
CONTROL_PORT = int(os.getenv("CONTROL_PORT"))
CONTROL_URL = f"http://{CONTROL_HOST}:{CONTROL_PORT}" 

CONTROL_HEADER = {
    "Content-Type": "application/json"
    }

router = APIRouter()

class VMBase(BaseModel):
    uuid: str

class VMStat(VMBase):
    type: str

# 추가된 VM 생성용 데이터 모델
class VMUser(BaseModel):
    name: str
    groups: str
    passWord: str
    ssh: List[str]

class VMHWInfo(BaseModel):
    memory: int
    cpu: int
    disk: int


class CreateVMRequest(VMBase):
    domType: str
    domName: str
    os: str
    netType: str
    HWInfo: VMHWInfo
    method: int
    users: List[VMUser]

sys_user = VMUser(
    name="doddle",
    groups="wheel",
    passWord="Doddle1234",
    ssh=[]
)

class CreateReq(BaseModel):
    name: str
    os_id: int
    ip: str
    type_id: int
    is_public: bool

class vmID(BaseModel):
    id: str

class vm_state(vmID):
    state: str

class vm_email(vmID):
    email: str

class vm_user(vmID):
    user: str

class VMNameUpdate(BaseModel):
    new_name: str

class VMStateUpdate(BaseModel):
    state: str

# VM 생성을 위한 정보 전달
@router.get("/")
async def vm_requirements_info(db_con2back: Session = Depends(get_db_con2web), current_user=Depends(get_current_user)):
    # InstanceType 전체 조회
    instance_types = db_con2back.query(InstanceTypes).all()

    # OS 전체 조회
    os_list = db_con2back.query(OsList).all()

    # 결과를 JSON 직렬화 가능한 형태로 변환
    return {
        "instance_types": [
            {
                "id": item.id,
                "typename": item.typename,
                "vcpu": item.vcpu,
                "ram": item.ram,
                "dsk": item.disk
            }
            for item in instance_types
        ],
        "os": [
            {
                "id": os.id,
                "name": os.name
            }
            for os in os_list
        ]
    }


# VM 생성
@router.post("/")
async def create_vm(data: CreateReq, db_web: Session = Depends(get_db_web), db_con2web: Session = Depends(get_db_con2web), current_user=Depends(get_current_user)):
    vm_id = str(uuid.uuid4())

    instance_type = db_con2web.query(InstanceTypes).filter(
        InstanceTypes.id == data.type_id
    ).first()

    if not instance_type:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid instance type: {data.type_id}"
        )
    
    os_row = db_con2web.query(OsList).filter(
        OsList.id == data.os_id
    ).first()

    if not os_row:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid OS: {data.os_id}"
        )
    
    reqdata = CreateVMRequest(
        domType="kvm",
        domName=vm_id,
        uuid=vm_id,
        os=os_row.name,
        netType="nat",
        HWInfo=VMHWInfo(
            memory=instance_type.ram,
            cpu=instance_type.vcpu,
            disk=instance_type.disk
        ),
        method=0,
        users=[sys_user]
    )

    print(reqdata)

    try:
        response = requests.post(
            f"{CONTROL_URL}/vm",
            data=json.dumps(reqdata.dict()),
            headers={"Content-Type": "application/json"}
        )
        print("json: ", json.dumps(reqdata.dict()))
        print("Status Code:", response.status_code)
        print("Raw Response:", response.text)

        # 안전하게 json 파싱 시도
        try:
            response_data = response.json()
            print("Parsed JSON:", response_data)
        except requests.exceptions.JSONDecodeError:
            response_data = response.text
            print("응답이 JSON이 아닙니다. 다음과 같은 응답을 받음:")
        print(response_data)

    except requests.exceptions.RequestException as e:
        print(f"요청 자체 실패: {e}")
        raise HTTPException(status_code=500, detail="Control 서버와 통신 실패")

    new_vm = VMs(
        vm_id=vm_id, 
        owner_id=current_user, 
        vm_name=data.name, 
        is_public=data.is_public,
        instance_type=data.type_id,
        os=data.os_id
    )
    db_web.add(new_vm)
    db_web.commit()
    db_web.refresh(new_vm)

    return {
        "msg": "VM created", 
        "vm_id": vm_id
    }

# VM 삭제
@router.delete("/{vm_id}")
async def delete_vm(vm_id: str, db: Session = Depends(get_db_web), current_user=Depends(get_current_user)):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id, VMs.owner_id == current_user).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    db.delete(vm)
    db.commit()

    response = requests.delete(
            f"{CONTROL_URL}/vm",
            data={"uuid": vm_id},
            headers={"Content-Type": "application/json"}
        )
    
    print("Status Code:", response.status_code)
    print("Raw Response:", response.text)

    # 안전하게 json 파싱 시도
    try:
        response_data = response.json()
        print("Parsed JSON:", response_data)
    except requests.exceptions.JSONDecodeError:
        response_data = response.text
        print("응답이 JSON이 아닙니다. 다음과 같은 응답을 받음:")
    print(response_data)

    return {
        "msg": "VM deleted"
    }

# VM 이름 변경
@router.patch("/{vm_id}/name")
async def change_vm_name(
    vm_id: str,
    payload: VMNameUpdate,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    # 현재 사용자가 소유한 VM인지 확인
    vm = db.query(VMs).filter(VMs.vm_id == vm_id, VMs.owner_id == current_user).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found or not owned by user")

    # 이름 변경
    vm.vm_name = payload.new_name
    db.commit()
    db.refresh(vm)

    return {
        "msg": "VM name changed successfully",
        "vm_id": vm.vm_id,
        "new_name": vm.vm_name
    }

@router.patch("/{vm_id}/state")
async def change_vm_status(
    vm_id: str,
    payload: VMStateUpdate,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    state = payload.state

    if state not in ["run", "stop", "terminate"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    match state:
        case "stop":
            target_url = f"{CONTROL_URL}/vm/shutdown"
            method = "POST"
            action_past = "stopped"
        case "run":
            target_url = f"{CONTROL_URL}/vm/start"
            method = "POST"
            action_past = "started"
        case "terminate":
            target_url = f"{CONTROL_URL}/vm"
            method = "DELETE"
            action_past = "terminated"
        case _:
            raise HTTPException(status_code=400, detail="Invalid status flow")

    try:
        response = requests.request(
            method=method,
            url=target_url,
            json={"uuid": vm_id},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            return {
                "msg": f"VM {action_past}",
                "status": "success"
            }
        else:
            return {
                "msg": f"VM {state} failed. {response.text}",
                "status": "failed"
            }
            
    except requests.exceptions.RequestException as e:
        return {
            "msg": f"Connection failed: {str(e)}",
            "status": "failed"
        }

# VM 접속 정보
@router.get("/{vm_id}/connect")
async def get_vm_connection_info(vm_id: str, db: Session = Depends(get_db_web), current_user=Depends(get_current_user)):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    response = requests.get(
            f"{CONTROL_URL}/vm/connect",
            params={"uuid": vm_id},
            headers={"Content-Type": "application/json"}
        )
        
    print("Status Code:", response.status_code)
    print("Raw Response:", response.text)
        
    # 안전하게 json 파싱 시도
    try:
        response_data = response.json()
        print("Parsed JSON:", response_data)
    except requests.exceptions.JSONDecodeError:
        response_data = response.text
        print("응답이 JSON이 아닙니다. 다음과 같은 응답을 받음:")
    print(response_data)

    guacamole_url = "https://doddle.kr/connect/?token="+response_data["authToken"]

    return {
        "url": guacamole_url
    }

# 모든 VM 상태
@router.get("/status")
async def get_all_vms(
    db: Session = Depends(get_db_web),
    db_con2: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    # 1. DB 쿼리 결과 Redis 캐싱 (30초)
    vm_cache_key = f"user:{current_user}:vms"
    cached_vms = redis_client.get(vm_cache_key)

    if cached_vms:
        vms = json.loads(cached_vms)
    else:
        # Owner 또는 Shared User에 해당하는 VM 모두 가져오기
        vms_query = (
            db.query(VMs, VmSharedUsers.user_id.label("shared_user_id"))
            .outerjoin(VmSharedUsers, VMs.vm_id == VmSharedUsers.vm_id)
            .filter(
                or_(
                    VMs.owner_id == current_user,
                    VmSharedUsers.user_id == current_user
                )
            )
            .all()
        )

        vms = []
        for vm, _ in vms_query:
            # owner 여부 판별
            is_owner = (vm.owner_id == current_user)

            # instance_type, os 상세 정보 조회
            instance_type_info = db_con2.query(InstanceTypes).filter(InstanceTypes.id == vm.instance_type).first()
            os_info = db_con2.query(OsList).filter(OsList.id == vm.os).first()

            vms.append({
                "vm_id": vm.vm_id,
                "vm_name": vm.vm_name,
                "is_owner": "admin" if is_owner else "user",
                "instance_type": instance_type_info.typename if instance_type_info else None,
                "os": os_info.name if os_info else None,
                "now": int(datetime.now(timezone.utc).timestamp())
            })

        # DB 캐싱 (30초 TTL, write 허용)
        redis_client.setex(vm_cache_key, 30, json.dumps(vms))

    # 2. VM 상태+IP는 Redis에서 **읽기만**
    vm_ids = [vm["vm_id"] for vm in vms]
    redis_values = redis_client.mget(vm_ids) if vm_ids else []

    result = []
    for vm, redis_value in zip(vms, redis_values):
        if redis_value is None:
            status = "unknown from control"
            ip = None
            uptime_str = "0H"
        else:
            try:
                value_dict = json.loads(redis_value)
                status = value_dict.get("status", "unknown from control")
                ip = value_dict.get("ip")
                
                now = datetime.fromtimestamp(vm["now"], timezone.utc)
                vm_time_ts = value_dict.get("time")
                if vm_time_ts:
                    uptime_delta = now - datetime.fromtimestamp(vm_time_ts, timezone.utc)
                    uptime_str = f"{uptime_delta.days}D {uptime_delta.seconds // 3600}H"
                else:
                    uptime_str = "0H"
            except Exception:
                status = "unknown from control"
                ip = None
                uptime_str = "0H"

        result.append({
            "vm_id": vm["vm_id"],
            "vm_name": vm["vm_name"],
            "is_owner": vm["is_owner"],
            "instance_type": vm["instance_type"],
            "os": vm["os"],
            "ip": ip,
            "status": status,
            "uptime": uptime_str
        })

    return result

# 특정 VM 상태
@router.get("/{vm_id}/status")
async def get_vm_status(
    vm_id: str,
    db: Session = Depends(get_db_web),
    db_con2: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    # VM 존재 여부 확인
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    # Redis에서 상태/네트워크/실행 시간 정보 읽기
    redis_value = redis_client.get(vm_id)
    if redis_value:
        try:
            redis_data = json.loads(redis_value)
            status = redis_data.get("status", "unknown")
            ip = redis_data.get("ip")
            uptime = redis_data.get("time")  # 실행 시간
        except Exception:
            status = "unknown"
            ip = None
            uptime = None
    else:
        status = "unknown"
        ip = None
        uptime = None

    # InstanceType 상세 정보
    instance_type_info = db_con2.query(InstanceTypes).filter(
        InstanceTypes.id == vm.instance_type
    ).first()

    # OS 상세 정보
    os_info = db_con2.query(OsList).filter(
        OsList.id == vm.os
    ).first()

    if uptime:
        uptime = datetime.now(timezone.utc) - datetime.fromtimestamp(uptime, timezone.utc)
        time_return =f"{uptime.days}D {uptime.seconds//3600}H"

    return {
        "vm_id": vm.vm_id,
        "vm_name": vm.vm_name,
        "status": status,
        "os": os_info.name if os_info else None,
        "instance_type": instance_type_info.typename if instance_type_info else None,
        "resources": {
            "vcpu": instance_type_info.vcpu if instance_type_info else None,
            "ram": instance_type_info.ram if instance_type_info else None,
            "disk": instance_type_info.disk if instance_type_info else None,
        },
        "network": {
            "ip": ip,
        },
        "time_info": {
            "start_time": vm.created_at.strftime("%Y-%m-%d %H:%M:%S") if vm.created_at else None,
            "uptime": time_return,
        }
    }

# 공유 사용자 초대 (처음엔 pending)
@router.post("/{vm_id}/shared-users")
async def add_shared_user(
    vm_id: str,
    email: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    if vm.owner_id != current_user:
        raise HTTPException(status_code=403, detail="Only admin can invite shared users")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    exists = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == user.id
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="User already invited")

    shared_entry = VmSharedUsers(
        id=str(uuid.uuid4()),
        vm_id=vm_id,
        user_id=user.id,
        status="pending"
    )
    db.add(shared_entry)
    db.commit()
    return {"msg": "Invitation sent (pending)"}


# 공유 사용자 수락
@router.patch("/{vm_id}/shared-users/accept")
async def accept_shared_user_invite(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    shared_entry = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == current_user,
        VmSharedUsers.status == "pending"
    ).first()

    if not shared_entry:
        raise HTTPException(status_code=404, detail="Pending invitation not found")

    # 7일 이상 지난 경우 자동 거절
    if shared_entry.created_at and shared_entry.created_at < datetime.utcnow() - timedelta(days=7):
        shared_entry.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Invitation expired and automatically rejected")

    shared_entry.status = "accepted"
    db.commit()
    return {"msg": "Invitation accepted"}


# 공유 사용자 거절
@router.patch("/{vm_id}/shared-users/reject")
async def reject_shared_user_invite(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    shared_entry = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == current_user,
        VmSharedUsers.status == "pending"
    ).first()

    if not shared_entry:
        raise HTTPException(status_code=404, detail="Pending invitation not found")

    shared_entry.status = "rejected"
    db.commit()
    return {"msg": "Invitation rejected"}


# 공유 사용자 삭제 (관리자만 가능)
@router.delete("/{vm_id}/shared-users/{user_id}")
async def remove_shared_user(
    vm_id: str,
    user_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    if vm.owner_id != current_user:
        raise HTTPException(status_code=403, detail="Only admin can remove shared users")

    shared_entry = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == user_id
    ).first()
    if not shared_entry:
        raise HTTPException(status_code=404, detail="Shared user not found")

    db.delete(shared_entry)
    db.commit()
    return {"msg": "Shared user removed"}


# 공유 사용자 목록 조회
@router.get("/{vm_id}/shared-users")
async def get_shared_users(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    # is_public = False 이고 admin이 아닌 경우 → 조회 불가
    if not vm.is_public and vm.owner_id != current_user:
        raise HTTPException(status_code=403, detail="You are not allowed to see shared users")

    shared_users = (
        db.query(User.id, User.username, User.email, VmSharedUsers.status, VmSharedUsers.created_at)
        .join(VmSharedUsers, User.id == VmSharedUsers.user_id)
        .filter(VmSharedUsers.vm_id == vm_id)
        .all()
    )

    return {
        "admin": vm.owner_id,
        "shared_users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "status": u.status,
                "invited_at": u.created_at
            } for u in shared_users
        ]
    }

#  관리자 변경 요청 (코드 발송)
@router.post("/{vm_id}/admin/change-request")
async def request_admin_change(
    vm_id: str,
    new_admin_email: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id, VMs.owner_id == current_user).first()
    if not vm:
        raise HTTPException(status_code=403, detail="Only current admin can request admin change")

    new_admin = db.query(User).filter(User.email == new_admin_email).first()
    if not new_admin:
        raise HTTPException(status_code=404, detail="New admin user not found")

    # 기존에 pending 요청이 있으면 중복 방지
    existing = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id,
        VmAdminChangeRequest.status == "pending"
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="There is already a pending admin change request")

    # 인증 코드 발송
    send_verification_email(new_admin.email, db)

    # DB 저장 (코드는 verification_codes 테이블에서 관리)
    req = VmAdminChangeRequest(
        vm_id=vm_id,
        old_admin_id=current_user,
        new_admin_id=new_admin.id,
        status="pending"
    )
    db.add(req)
    db.commit()

    return {"msg": f"Verification email sent to {new_admin.email}"}


#  관리자 변경 확인 (코드 검증 후 관리자 변경)

@router.post("/{vm_id}/admin/verify")
async def verify_admin_change(
    vm_id: str,
    email: str,
    code: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    req = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id,
        VmAdminChangeRequest.status == "pending"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="No pending admin change request found")

    # 7일 이상 지난 요청은 자동 거절
    if req.created_at < datetime.utcnow() - timedelta(days=7):
        req.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Admin change request expired and rejected")

    # 초대된 새로운 관리자만 인증 가능
    new_admin = db.query(User).filter(User.id == req.new_admin_id).first()
    if not new_admin or new_admin.id != current_user:
        raise HTTPException(status_code=403, detail="Only the invited admin can verify")

    # 이메일 코드 검증
    if not verify_code(email, code, db):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # 관리자 변경
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    vm.owner_id = new_admin.id
    req.status = "verified"
    db.commit()

    return {"msg": "Admin changed successfully"}

#  관리자 변경 거절
@router.patch("/{vm_id}/admin/reject")
async def reject_admin_change(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    req = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id,
        VmAdminChangeRequest.status == "pending"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="No pending admin change request found")

    # 7일 이상 지난 요청은 자동 거절
    if req.created_at < datetime.utcnow() - timedelta(days=7):
        req.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Admin change request expired and rejected")

    # 초대된 새로운 관리자만 거절 가능
    if req.new_admin_id != current_user:
        raise HTTPException(status_code=403, detail="Only the invited admin can reject")

    req.status = "rejected"
    db.commit()
    return {"msg": "Admin change request rejected"}


#  관리자 변경 요청 조회
@router.get("/{vm_id}/admin/change-request")
async def get_admin_change_request(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    req = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id
    ).order_by(VmAdminChangeRequest.created_at.desc()).first()

    if not req:
        return {"msg": "No admin change request"}

    return {
        "vm_id": req.vm_id,
        "old_admin_id": req.old_admin_id,
        "new_admin_id": req.new_admin_id,
        "status": req.status,
        "requested_at": req.created_at
    }
