from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from bson import ObjectId
from typing import Annotated
from datetime import datetime, timedelta
from models import User, UserInDB, Token, TokenData
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Annotated
from database import collection_user
from schemas import individual_user, list_users

SECRET_KEY = "8afe2ba284e85a5483e102adc1e5ffef5a831dd11054fb52284fe0d245863051"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter()

pwd_context = CryptContext(schemes =['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# db = {
#     "tim": {
#         "username": "tim",
#         "full_name": "Tim Ruscica",
#         "email": "tim@gmail.com",
#         "hashed_password": "$2b$12$KjTcgQ5NlYYuqfUUmBArPefFB8tBW.3dZHll1mjj//7WFXNhLyg8m",
#         "disabled": False
#     },
#     "jose": {
#         "username": "jose",
#         "full_name": "Jose Oviedo",
#         "email": "jose@gmail.com",
#         "hashed_password": "$2b$12$KjTcgQ5NlYYuqfUUmBArPefFB8tBW.3dZHll1mjj//7WFXNhLyg8m",
#         "disabled": False
#     }
# }

######################
# AUTH
######################

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    user = collection_user.find_one({"username": username})
    if user:
        return UserInDB(**user)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    print("authenticate_user:", user)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                        detail="No se han podido validar las credenciales", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credential_exception
        
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    
    user = get_user(username=token_data.username)
    if user is None:
        raise credential_exception
    
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuario inactivo")
    
    return current_user

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="No se han podido validar las credenciales", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={'sub': user.username}, expires_delta=access_token_expires)
    return {'access_token': access_token, 'token_type': 'bearer'}

@router.post("/adduser/")
async def create_user(user: User):
    collection_user.insert_one(dict(user))
    return (
        {
            "message": f"Usuario {user.full_name} creado.",
            "user": user
        }
    )

@router.get("/users")
async def get_users(current_user: User = Depends(get_current_user)):
    return list_users(collection_user.find())

@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/users/me/items")
async def read_own_items(current_user: Annotated[User, Depends(get_current_user)]):
    return [{'item_id': 1, 'owner':current_user}]

######################
# RESIDENTIALS
######################

#GET Conjuntos
@router.get("/")
async def test():
    return {"Hello": "world!"}

@router.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}