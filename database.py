from pymongo import MongoClient

client = MongoClient("mongodb://root:secret@localhost:27017")

db = client.users

collection_user = db["user"]