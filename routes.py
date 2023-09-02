from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from bson import ObjectId
from typing import Annotated

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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