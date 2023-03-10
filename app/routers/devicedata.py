from config.config import Setting
from fastapi import APIRouter,Request,Form,HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
app = APIRouter()
TEMPLATES = Jinja2Templates(directory="templates")
from pydantic import BaseModel


@app.get("/devicedata",response_class = HTMLResponse)
def devicedata_get(request:Request):
   return TEMPLATES.TemplateResponse("devicedata.html",{"request":request})