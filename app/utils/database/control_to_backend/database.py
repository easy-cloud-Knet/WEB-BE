from app.utils.database.database import Database
import os
from dotenv import load_dotenv

#load_dotenv()

database = Database(
    os.getenv("DATABASE_CON2BACK"), 
    ['InstanceType', 'os'])
database.init_database()

get_db = database.get_db