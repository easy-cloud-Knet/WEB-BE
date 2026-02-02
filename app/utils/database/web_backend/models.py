from app.utils.database.web_backend.database import database

User = database.create_model('users')
VMs = database.create_model('virtual_machines')
VerificationCode = database.create_model('verification_codes')
VmSharedUsers = database.create_model('vm_shared_users')
VmAdminChangeRequest = database.create_model('vm_admin_change_requests')