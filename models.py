from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Annotated

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
  access_token: str
  token_type: str

class TokenData(BaseModel):
  username: str | None = None

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
  hashed_password: str

