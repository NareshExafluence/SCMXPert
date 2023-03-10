from config.config import Setting
from fastapi import APIRouter,Request,Form,HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
app = APIRouter()
TEMPLATES = Jinja2Templates(directory="templates")
from pydantic import BaseModel
from passlib.context import CryptContext



PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(password: str):
   """Function to change plain password to Hash"""
   return PWD_CONTEXT.hash(password)
def verify_password(password: str, hashed_password: str):
   """Function to verify hased password"""
   return PWD_CONTEXT.verify(password, hashed_password)

class login(BaseModel):
   Email: str
   Password: str




@app.get("/login",response_class = HTMLResponse)
def login_get(request:Request):
   return TEMPLATES.TemplateResponse("login.html",{"request":request})
   
@app.post("/dashboard",response_class = HTMLResponse)
def login_post(request:Request, email:str=Form(...),password:str=Form(...)):
   login_data = login(Email=email,Password=password)
   user = Setting.Signup.find_one({"Email":email})
   if not user:
      return TEMPLATES.TemplateResponse("login.html",{"request":request,"email":"User Not Registred yet!"})
   else:
      if not verify_password(password,user['Password'] ):

         login_data = Setting.Login.insert_one(login_data.dict())
         return TEMPLATES.TemplateResponse("login.html",{"request":request,"credentials":"Invalid Credentials"})
      return TEMPLATES.TemplateResponse("dashboard.html",{"request":request,"User":user['Username']})
      
      
   
   





  




