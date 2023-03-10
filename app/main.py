from fastapi import FastAPI
from routers import index,login,signup,dashboard,shipment,devicedata,password
from fastapi.staticfiles import StaticFiles
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(index.app)
app.include_router(login.app)
app.include_router(signup.app)
app.include_router(dashboard.app)
app.include_router(shipment.app)
app.include_router(devicedata.app)
app.include_router(password.app)



