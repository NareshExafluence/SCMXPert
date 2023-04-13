#Importing the Required Packages
import datetime as dt
from config.config import Environment
from fastapi import APIRouter,Request,HTTPException, status, Depends, Response
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
# from routers.login2 import login
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Dict, Optional
from jose import JWTError, jwt
app = APIRouter()


#BaseModel for Login form
class login(BaseModel):
   Email: str
   Password: str


class OAuth2PasswordBearerWithCookie(OAuth2):
    
 def __init__(self,tokenUrl: str,scheme_name: Optional[str] = None,scopes: Optional[Dict[str, str]] = None,description: Optional[str] = None,auto_error: bool = True):
       if not scopes:
          scopes = {}
       flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
       super().__init__(flows=flows,scheme_name=scheme_name,description=description,auto_error=auto_error)

 async def __call__(self, request: Request) -> Optional[str]:
    authorization: str = request.cookies.get(Environment.cookie_name)
    scheme, param = get_authorization_scheme_param(authorization)
    if not authorization or scheme.lower() != "bearer":
        if self.auto_error:
            raise HTTPException(
               status_code=status.HTTP_401_UNAUTHORIZED,
               detail="Not authenticated",
               headers={"WWW-Authenticate": "Bearer"},
               )
        else:
            return None
    return param

OAUTH2_SCHEME = OAuth2PasswordBearerWithCookie(tokenUrl="token")

#Authenticating  the user by email,password entered in login form 
def authenticating_user(email: str, password: str) -> login:
    user = fetching_user(email)
    if not user:
        return False
    if not password_verification(password, user['Password']):
        return False
    return user


#Checking the user is existed or not in signup collection using email entered in login form
def fetching_user(email: str) -> login:
    user = Environment.signup.find_one({"Email":email})
    if user:
        return user
    return None

#Password dehashing function
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
def password_verification(password: str, hashed_password: str):
   #Function to verify hased password
   return PWD_CONTEXT.verify(password, hashed_password)

#Generating JWT_token using user email,secret_key and HS256 algorithm.
def generating_token(data: Dict) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=Environment.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode,Environment.secret_key,algorithm=Environment.algorithm)
    return encoded_jwt

#Getting the active user from the cookie
def active_user_from_cookie(request: Request) -> login:
    token = request.cookies.get(Environment.cookie_name)
    user = decode_token(token)
    return user

#Getting the active user from the token
def active_user_from_token(token: str = Depends(OAUTH2_SCHEME)) -> login:
    user = decode_token(token)
    return user

#Decoding the JWT_token using same secret_key, HS256 algorithm and getting the username(email).
def decode_token(token: str) -> login:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session Timeout, Login Again! "
    )
    token = str(token).replace("Bearer", "").strip()
    try:
        payload = jwt.decode(token, Environment.secret_key, algorithms=[Environment.algorithm])
        email: str = payload.get("email")
        if email is None:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

#-------------------------------------------
#Post method for the token
#--------------------------------------------

@app.post("/token")
def login_for_access_token(response: Response,form_data: OAuth2PasswordRequestForm = Depends()) -> Dict[str, str]:
    # Authenticate the user with the provided credentials
    user = authenticating_user(form_data.email, form_data.password)
    if not user:
        # If the user is not authenticated, raise an HTTPException with 401 status code
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid email or password')
    # Create an access token for the authenticated user
    access_token = generating_token(data={"email": user["Email"]})
    # Set an HttpOnly cookie in the response. `httponly=True` prevents
    # JavaScript from reading the cookie.
    response.set_cookie(
        key=Environment.cookie_name,
        value=f"Bearer {access_token}",
        httponly=True
    )
    # Return the access token and token type in a dictionary
    return {Environment.cookie_name: access_token, "token_type": "bearer"}