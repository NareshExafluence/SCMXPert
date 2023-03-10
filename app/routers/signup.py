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

class signup(BaseModel):
    Username: str
    Email:str
    Password: str
    ConfirmPassword: str

@app.get("/signup",response_class = HTMLResponse)
def signup_get(request:Request):
   return TEMPLATES.TemplateResponse("signup.html",{"request":request})


@app.post("/signup",response_class = HTMLResponse)
def signup_post(request:Request, username:str=Form(...),email:str=Form(...),password:str=Form(...),cnfpassword:str=Form(...)):

   hashed_password = hash_password(password)
   signup_data = signup(Username=username,Email=email,Password=hashed_password,ConfirmPassword=hashed_password)
   data = Setting.Signup.find_one({"Email":email})
   try:
      if not data and (password == cnfpassword):
         Setting.Signup.insert_one(signup_data.dict())
         return HTMLResponse("<script>window.location.href = '/login';</script>")
      return TEMPLATES.TemplateResponse("signup.html", {"request":request, "Email_Existed":"Email already exists"})
       
   except Exception as exc: 
      raise HTTPException(status_code=500, detail="Internal Server Error") from exc