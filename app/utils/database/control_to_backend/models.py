from app.utils.database.control_to_backend.database import database

InstanceTypes = database.create_model('InstanceType')
OsList = database.create_model('os')