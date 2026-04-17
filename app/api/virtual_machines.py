from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
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

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=0,
    decode_responses=True
)

CONTROL_HOST = os.getenv("CONTROL_HOST")
CONTROL_PORT = int(os.getenv("CONTROL_PORT"))
CONTROL_URL = f"http://{CONTROL_HOST}:{CONTROL_PORT}"

router = APIRouter()


# ── Pydantic models ───────────────────────────────────────────────────────────

class VMUser(BaseModel):
    name: str
    groups: str
    passWord: str
    ssh: List[str]

class VMHWInfo(BaseModel):
    memory: int
    cpu: int
    disk: int

class VMBase(BaseModel):
    uuid: str

class CreateVMRequest(VMBase):
    domType: str
    domName: str
    os: str
    netType: str
    HWInfo: VMHWInfo
    method: int
    users: List[VMUser]

sys_user = VMUser(name="doddle", groups="wheel", passWord="Doddle1234", ssh=[])

class CreateReq(BaseModel):
    name: str
    os_id: int
    ip: str
    type_id: int

class VMNameUpdate(BaseModel):
    new_name: str

class VMStateUpdate(BaseModel):
    state: str


# ── VM requirements ───────────────────────────────────────────────────────────

@router.get("/", summary="VM 생성 옵션 조회")
async def vm_requirements_info(
    db_con2back: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    instance_types = db_con2back.query(InstanceTypes).all()
    os_list = db_con2back.query(OsList).all()
    return {
        "instance_types": [
            {"id": i.id, "typename": i.typename, "vcpu": i.vcpu, "ram": i.ram, "dsk": i.disk}
            for i in instance_types
        ],
        "os": [{"id": o.id, "name": o.name} for o in os_list]
    }


# ── VM CRUD ───────────────────────────────────────────────────────────────────

@router.post("/", summary="VM 생성")
async def create_vm(
    data: CreateReq,
    db_web: Session = Depends(get_db_web),
    db_con2web: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    vm_id = str(uuid.uuid4())

    instance_type = db_con2web.query(InstanceTypes).filter(InstanceTypes.id == data.type_id).first()
    if not instance_type:
        raise HTTPException(status_code=400, detail=f"Invalid instance type: {data.type_id}")

    os_row = db_con2web.query(OsList).filter(OsList.id == data.os_id).first()
    if not os_row:
        raise HTTPException(status_code=400, detail=f"Invalid OS: {data.os_id}")

    reqdata = CreateVMRequest(
        domType="kvm", domName=vm_id, uuid=vm_id, os=os_row.name, netType="nat",
        HWInfo=VMHWInfo(memory=instance_type.ram, cpu=instance_type.vcpu, disk=instance_type.disk),
        method=0, users=[sys_user]
    )

    try:
        response = requests.post(
            f"{CONTROL_URL}/vm",
            data=json.dumps(reqdata.dict()),
            headers={"Content-Type": "application/json"}
        )
        try:
            response.json()
        except requests.exceptions.JSONDecodeError:
            pass
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=500, detail="Control 서버와 통신 실패")

    new_vm = VMs(
        vm_id=vm_id, owner_id=current_user, vm_name=data.name,
        instance_type=data.type_id, os=data.os_id
    )
    db_web.add(new_vm)
    db_web.commit()
    db_web.refresh(new_vm)
    return {"msg": "VM created", "vm_id": vm_id}

@router.delete("/{vm_id}", summary="VM 삭제")
async def delete_vm(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    if vm.owner_id != current_user:
        raise HTTPException(status_code=403, detail="Only the VM owner can delete it")
 
    db.delete(vm)
    db.commit()
 
    try:
        requests.delete(f"{CONTROL_URL}/vm", json={"uuid": vm_id},
                        headers={"Content-Type": "application/json"})
    except requests.exceptions.RequestException:
        pass
 
    return {"msg": "VM deleted"}

@router.patch("/{vm_id}/name", summary="VM 이름 변경")
async def change_vm_name(
    vm_id: str,
    payload: VMNameUpdate,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    if vm.owner_id != current_user:
        raise HTTPException(status_code=403, detail="Only the VM owner can rename it")
 
    vm.vm_name = payload.new_name
    db.commit()
    db.refresh(vm)
    return {"msg": "VM name changed successfully", "vm_id": vm.vm_id, "new_name": vm.vm_name}

# ── VM state & status ─────────────────────────────────────────────────────────

@router.patch("/{vm_id}/state", summary="VM 상태 변경 (run / stop / terminate)")
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
        case "stop":      target_url, method, action_past = f"{CONTROL_URL}/vm/shutdown", "POST",   "stopped"
        case "run":       target_url, method, action_past = f"{CONTROL_URL}/vm/start",    "POST",   "started"
        case "terminate": target_url, method, action_past = f"{CONTROL_URL}/vm",          "DELETE", "terminated"
        case _: raise HTTPException(status_code=400, detail="Invalid status flow")

    try:
        response = requests.request(method=method, url=target_url,
                                    json={"uuid": vm_id}, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            return {"msg": f"VM {action_past}", "status": "success"}
        return {"msg": f"VM {state} failed. {response.text}", "status": "failed"}
    except requests.exceptions.RequestException as e:
        return {"msg": f"Connection failed: {str(e)}", "status": "failed"}


@router.get("/status", summary="내 VM 전체 목록 및 상태")
async def get_all_vms(
    db: Session = Depends(get_db_web),
    db_con2: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    vm_cache_key = f"user:{current_user}:vms"
    cached_vms = redis_client.get(vm_cache_key)

    if cached_vms:
        vms = json.loads(cached_vms)
    else:
        owned_vms = db.query(VMs).filter(VMs.owner_id == current_user).all()

        accepted_shared_vm_ids = [
            row.vm_id for row in
            db.query(VmSharedUsers.vm_id).filter(
                VmSharedUsers.user_id == current_user,
                VmSharedUsers.status == "accepted"
            ).all()
        ]

        shared_vms = []
        if accepted_shared_vm_ids:
            shared_vms = db.query(VMs).filter(
                VMs.vm_id.in_(accepted_shared_vm_ids),
                VMs.owner_id != current_user
            ).all()

        vms = []
        for vm, role in [(v, "admin") for v in owned_vms] + [(v, "user") for v in shared_vms]:
            it = db_con2.query(InstanceTypes).filter(InstanceTypes.id == vm.instance_type).first()
            os = db_con2.query(OsList).filter(OsList.id == vm.os).first()
            vms.append({
                "vm_id": vm.vm_id, "vm_name": vm.vm_name, "is_owner": role,
                "instance_type": it.typename if it else None,
                "os": os.name if os else None,
                "now": int(datetime.now(timezone.utc).timestamp())
            })

        redis_client.setex(vm_cache_key, 30, json.dumps(vms))

    vm_ids = [vm["vm_id"] for vm in vms]
    redis_values = redis_client.mget(vm_ids) if vm_ids else []

    result = []
    for vm, redis_value in zip(vms, redis_values):
        status, ip, uptime_str = "unknown from control", None, "0H"
        if redis_value:
            try:
                d = json.loads(redis_value)
                status = d.get("status", "unknown from control")
                ip = d.get("ip")
                ts = d.get("time")
                if ts:
                    delta = datetime.fromtimestamp(vm["now"], timezone.utc) - datetime.fromtimestamp(ts, timezone.utc)
                    uptime_str = f"{delta.days}D {delta.seconds // 3600}H"
            except Exception:
                pass

        result.append({
            "vm_id": vm["vm_id"], "vm_name": vm["vm_name"], "is_owner": vm["is_owner"],
            "instance_type": vm["instance_type"], "os": vm["os"],
            "ip": ip, "status": status, "uptime": uptime_str
        })

    return result


@router.get("/{vm_id}/status", summary="특정 VM 상세 상태")
async def get_vm_status(
    vm_id: str,
    db: Session = Depends(get_db_web),
    db_con2: Session = Depends(get_db_con2web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    status, ip, uptime_ts = "unknown", None, None
    redis_value = redis_client.get(vm_id)
    if redis_value:
        try:
            d = json.loads(redis_value)
            status = d.get("status", "unknown")
            ip = d.get("ip")
            uptime_ts = d.get("time")
        except Exception:
            pass

    it = db_con2.query(InstanceTypes).filter(InstanceTypes.id == vm.instance_type).first()
    os_info = db_con2.query(OsList).filter(OsList.id == vm.os).first()

    time_return = "0H"
    if uptime_ts:
        delta = datetime.now(timezone.utc) - datetime.fromtimestamp(uptime_ts, timezone.utc)
        time_return = f"{delta.days}D {delta.seconds // 3600}H"

    return {
        "vm_id": vm.vm_id, "vm_name": vm.vm_name, "status": status,
        "os": os_info.name if os_info else None,
        "instance_type": it.typename if it else None,
        "resources": {
            "vcpu": it.vcpu if it else None,
            "ram": it.ram if it else None,
            "disk": it.disk if it else None,
        },
        "network": {"ip": ip},
        "time_info": {
            "start_time": vm.created_at.strftime("%Y-%m-%d %H:%M:%S") if vm.created_at else None,
            "uptime": time_return,
        }
    }


@router.get("/{vm_id}/connect", summary="VM 접속 URL 조회 (Guacamole)")
async def get_vm_connection_info(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    try:
        response = requests.get(f"{CONTROL_URL}/vm/connect", params={"uuid": vm_id},
                                headers={"Content-Type": "application/json"})
        token = response.json()["authToken"]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Control 서버 응답 오류: {str(e)}")

    return {"url": f"https://doddle.kr/connect/?token={token}"}


# ── Shared users ──────────────────────────────────────────────────────────────
#
# 라우트 등록 순서 규칙 (FastAPI first-match wins):
#   정적 경로(/leave, /accept, /reject, /invitations)를
#   동적 경로(/{user_id})보다 반드시 먼저 등록해야 함.
#
# 전체 플로우:
#   1. admin이 초대       POST   /{vm_id}/shared-users
#   2. user가 초대 확인   GET    /shared-users/invitations 
#   3. user가 수락        PATCH  /{vm_id}/shared-users/accept
#   4. user가 거절        PATCH  /{vm_id}/shared-users/reject
#   5. user가 자발 탈퇴   DELETE /{vm_id}/shared-users/leave 
#   6. admin이 강제 제거  DELETE /{vm_id}/shared-users/{user_id}
#   7. 목록 조회          GET    /{vm_id}/shared-users

@router.post("/{vm_id}/shared-users", summary="공유 사용자 초대")
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
    if user.id == current_user:
        raise HTTPException(status_code=400, detail="Cannot invite yourself")

    exists = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id, VmSharedUsers.user_id == user.id
    ).first()

    if exists:
        if exists.status in ("pending", "accepted"):
            raise HTTPException(status_code=400, detail="User already invited or accepted")
        exists.status = "pending"
        exists.created_at = datetime.now(timezone.utc)
        db.commit()
        return {"msg": "Re-invitation sent (pending)"}

    db.add(VmSharedUsers(vm_id=vm_id, user_id=user.id, status="pending"))
    db.commit()
    return {"msg": "Invitation sent (pending)"}

@router.get("/shared-users/invitations", summary="나에게 온 공유 초대 및 관리자 변경 요청 목록 조회")
async def get_my_invitations(
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    # 공유 사용자 초대 목록
    shared_rows = (
        db.query(VmSharedUsers, VMs)
        .join(VMs, VmSharedUsers.vm_id == VMs.vm_id)
        .filter(VmSharedUsers.user_id == current_user)
        .order_by(VmSharedUsers.created_at.desc())
        .all()
    )
 
    # 관리자 변경 요청 목록 (pending만)
    admin_rows = (
        db.query(VmAdminChangeRequest, VMs)
        .join(VMs, VmAdminChangeRequest.vm_id == VMs.vm_id)
        .filter(
            VmAdminChangeRequest.new_admin_id == current_user,
            VmAdminChangeRequest.status == "pending"
        )
        .order_by(VmAdminChangeRequest.created_at.desc())
        .all()
    )
 
    return {
        "shared_user_invitations": [
            {
                "vm_id":      entry.vm_id,
                "vm_name":    vm.vm_name,
                "owner_id":   vm.owner_id,
                "status":     entry.status,
                "invited_at": entry.created_at,
            }
            for entry, vm in shared_rows
        ],
        "admin_change_requests": [
            {
                "vm_id":        req.vm_id,
                "vm_name":      vm.vm_name,
                "old_admin_id": req.old_admin_id,
                "requested_at": req.created_at,
            }
            for req, vm in admin_rows
        ],
    }


@router.patch("/{vm_id}/shared-users/accept", summary="공유 초대 수락")
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

    if shared_entry.created_at:
        created_at = shared_entry.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at < datetime.now(timezone.utc) - timedelta(days=7):
            shared_entry.status = "rejected"
            db.commit()
            raise HTTPException(status_code=400, detail="Invitation expired and automatically rejected")

    shared_entry.status = "accepted"
    db.commit()
    return {"msg": "Invitation accepted"}


@router.patch("/{vm_id}/shared-users/reject", summary="공유 초대 거절")
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


@router.delete("/{vm_id}/shared-users/leave", summary="공유 VM에서 자발적 탈퇴")
async def leave_shared_vm(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    if vm.owner_id == current_user:
        raise HTTPException(status_code=400, detail="Owner cannot leave. Use admin transfer instead.")

    shared_entry = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == current_user
    ).first()
    if not shared_entry:
        raise HTTPException(status_code=404, detail="You are not a shared user of this VM")

    db.delete(shared_entry)
    db.commit()
    return {"msg": "Successfully left the shared VM"}


@router.delete("/{vm_id}/shared-users/{user_id}", summary="공유 사용자 강제 제거 (admin 전용)")
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
        VmSharedUsers.vm_id == vm_id, VmSharedUsers.user_id == user_id
    ).first()
    if not shared_entry:
        raise HTTPException(status_code=404, detail="Shared user not found")

    db.delete(shared_entry)
    db.commit()
    return {"msg": "Shared user removed"}


@router.get("/{vm_id}/shared-users", summary="공유 사용자 목록 조회")
async def get_shared_users(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    is_shared = db.query(VmSharedUsers).filter(
        VmSharedUsers.vm_id == vm_id,
        VmSharedUsers.user_id == current_user,
        VmSharedUsers.status == "accepted"
    ).first()

    if vm.owner_id != current_user and not is_shared:
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
            {"id": u.id, "username": u.username, "email": u.email,
             "status": u.status, "invited_at": u.created_at}
            for u in shared_users
        ]
    }


# ── Admin transfer ────────────────────────────────────────────────────────────

@router.post("/{vm_id}/admin/change-request", summary="관리자 변경 요청 (이메일 발송)")
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
 
    existing = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id, VmAdminChangeRequest.status == "pending"
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="There is already a pending admin change request")
 
    send_verification_email(new_admin.email, db)
 
    db.add(VmAdminChangeRequest(
        vm_id=vm_id, old_admin_id=current_user, new_admin_id=new_admin.id, status="pending"
    ))
    db.commit()
    return {"msg": f"Verification email sent to {new_admin.email}"}


@router.post("/{vm_id}/admin/verify", summary="관리자 변경 코드 검증 및 확정")
async def verify_admin_change(
    vm_id: str,
    code: str,                          # email 파라미터 제거
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    req = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id, VmAdminChangeRequest.status == "pending"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="No pending admin change request found")

    created_at = req.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if created_at < datetime.now(timezone.utc) - timedelta(days=7):
        req.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Admin change request expired and rejected")

    new_admin = db.query(User).filter(User.id == req.new_admin_id).first()
    if not new_admin or new_admin.id != current_user:
        raise HTTPException(status_code=403, detail="Only the invited admin can verify")

    if not verify_code(new_admin.email, code, db):   # users 테이블에서 조회한 email 사용
        raise HTTPException(status_code=400, detail="Invalid verification code")

    vm = db.query(VMs).filter(VMs.vm_id == vm_id).first()
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")

    vm.owner_id = new_admin.id
    req.status = "verified"
    db.commit()
    return {"msg": "Admin changed successfully"}


@router.patch("/{vm_id}/admin/reject", summary="관리자 변경 거절")
async def reject_admin_change(
    vm_id: str,
    db: Session = Depends(get_db_web),
    current_user=Depends(get_current_user)
):
    req = db.query(VmAdminChangeRequest).filter(
        VmAdminChangeRequest.vm_id == vm_id, VmAdminChangeRequest.status == "pending"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="No pending admin change request found")

    created_at = req.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if created_at < datetime.now(timezone.utc) - timedelta(days=7):
        req.status = "rejected"
        db.commit()
        raise HTTPException(status_code=400, detail="Admin change request expired and rejected")

    if req.new_admin_id != current_user:
        raise HTTPException(status_code=403, detail="Only the invited admin can reject")

    req.status = "rejected"
    db.commit()
    return {"msg": "Admin change request rejected"}


@router.get("/{vm_id}/admin/change-request", summary="관리자 변경 요청 조회")
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
        "vm_id": req.vm_id, "old_admin_id": req.old_admin_id,
        "new_admin_id": req.new_admin_id, "status": req.status,
        "requested_at": req.created_at
    }