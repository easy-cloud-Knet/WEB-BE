from app.utils.database.database import Database
import os
from dotenv import load_dotenv

load_dotenv()

database = Database(
    os.getenv("DATABASE_BACKEND"), 
    ['users', 'virtual_machines', 'verification_codes', 'vm_shared_users', 'vm_admin_change_requests']
)
database.init_database()
get_db = database.get_db