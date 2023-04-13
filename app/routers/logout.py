#Importing the Required Packages
from config.config import Environment
from fastapi import APIRouter,Request,HTTPException
from fastapi.responses import HTMLResponse,RedirectResponse
from fastapi.templating import Jinja2Templates
app = APIRouter()
TEMPLATES = Jinja2Templates(directory="templates")



@app.get("/logout", response_class=HTMLResponse)
def logout_get():
    """
    Handle a GET request to the logout endpoint.
    This function deletes the authentication cookie and redirects the user to the root page ("/").
    The authentication cookie is deleted by setting its value to an empty string and setting its
    max age to 0. This ensures that the browser deletes the cookie on the client side.
    :return: A `RedirectResponse` object that redirects the user to the root page ("/").
    """
    try:
        response = RedirectResponse(url="/login")
        response.delete_cookie(Environment.cookie_name)
        return response
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="Cookie name not found.") from exc
    except Exception as exception:
        raise HTTPException(status_code=500, detail=str(exception)) from exception