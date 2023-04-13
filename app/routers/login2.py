#Importing the Required Packages
import datetime as dt
from config.config import Environment
from fastapi import APIRouter,Request,Form,HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from routers.authentication import login_for_access_token
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Dict, List, Optional
app = APIRouter()
TEMPLATES = Jinja2Templates(directory="templates")

#Password hashing and dehashing function
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
def password_verification(password: str, hashed_password: str):
   #Function to verify hased password
   return PWD_CONTEXT.verify(password, hashed_password)

#BaseModel for Login form
class login(BaseModel):
   Email: str
   Password: str


#Backend Validation for the login form
class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: str= ""
        self.email: Optional[str] = None
        self.password: Optional[str] = None

#Getting email and password entered by user at Login time.
    async def load_data(self):
        form = await self.request.form()
        self.email = form.get("email")
        self.password = form.get("password")

#Validating email contains @ or not and password should have atleast 8 characters
    async def is_valid(self):
        if not self.email or not (self.email.__contains__("@")):
            self.errors="Email is required"
        if not self.password or not len(self.password) >= 8:
            self.errors="valid password is required"
        if not self.errors:
            return True
        return False

#--------------------------------------------
#Login Get Method
#--------------------------------------------

@app.get("/login",response_class = HTMLResponse)
def login_get(request:Request):
   return TEMPLATES.TemplateResponse("login.html",{"request":request})

#--------------------------------------------------
#Login Post Method
#---------------------------------------------------

@app.post("/login",response_class = HTMLResponse)
async def login_post(request:Request, email:str=Form(...),password:str=Form(...)):
   form = LoginForm(request)
   await form.load_data()
   try:
      if not await form.is_valid():
            # Form data is not valid
            raise HTTPException(status_code=400, detail="Please Enter Valid Details")
        # Form data is valid, generate new access token
      response = RedirectResponse("/dashboard", status.HTTP_302_FOUND)

      login_for_access_token(response=response, form_data=form)
    #   form.__dict__.update(message="Login Successful!")
      return response

   except HTTPException as exception:
      # Catch HTTPException and update form with error message
      form.__dict__.update(message="Invalid email or password")
    #   form.__dict__.get("errors").append(exception.detail)
      return TEMPLATES.TemplateResponse("login.html", form.__dict__)

   except Exception as exception:
      # Catch any other exception and return 500 Internal Server Error
      raise HTTPException(status_code=500, detail=str(exception)) from exception