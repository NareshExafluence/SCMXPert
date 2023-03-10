import os
import pymongo
from dotenv import load_dotenv
load_dotenv()
class settings:
    client = pymongo.MongoClient(os.getenv("mongouri"))
    db = client["SCM_Training"]
    DeviceData = db["DeviceData"]
    Shipments = db["Shipments"]
    Login = db["Login"]
    Signup = db["Signup"]
Setting = settings()
