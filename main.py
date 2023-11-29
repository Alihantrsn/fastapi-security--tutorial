from ctypes import Union
from typing import Literal
from fastapi import Depends, FastAPI, HTTPException, Path, Query, UploadFile,File, status
from pydantic import BaseModel, EmailStr
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
app = FastAPI()



oauth2_schema=OAuth2PasswordBearer(tokenUrl="token")
fake_user_db={
    "johndoe":dict(
        username="johndoe",
        full_name="John Doo",
        email="johndoo@example.com",
        hashed_password="fakehashedsecret",
        disable=False
    ),
    "alice":dict(
        username="aliceWonder",
        full_name="Alice Wonderland",
        email="aliceinwonderland@example.com",
        hashed_password="fakehashedsecret2",
        disable=True
    )
}


def fake_hash_password(password: str):
    return f"fakehashed{password}"

class User(BaseModel):
    username:str
    email:EmailStr
    full_name:str|None=None
    disable:bool|None=None

class UserInDb(User):
    hashed_password:str

def get_user(db, username:str):
    if username in db:
        user_dict=db[username]
        return UserInDb(**user_dict)

def fake_decode_token(token):
    return get_user(fake_user_db,token)
    

async def get_current_user(token:str=Depends(oauth2_schema)):
    user=fake_decode_token(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid authentication credentials",
                            headers={"WWW-Authenticate":"Bearer"})
    return user

async def get_current_active_user(current_user:User=Depends(get_current_user)):
    if current_user.disable:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Inactive user")
    return current_user



@app.get("/users/me")
async def get_me(current_user:User=Depends(get_current_user)):
    return current_user
    
@app.post("/token")
async def login(form_data:OAuth2PasswordRequestForm=Depends()):
    user_dict=fake_user_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Incorrect username or password")
    user=UserInDb(**user_dict)
    hashed_password=fake_hash_password(form_data.password)
    if not hashed_password==user.hashed_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Incorrect username or password")
    return {"access_token":user.username, "token_type":"Bearer"}


@app.get("/items")
async def read_items(token:str=Depends(oauth2_schema)):
    return {"token":token}
    






