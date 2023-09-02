from pymongo import MongoClient

client = MongoClient("mongodb://root:secret@localhost:27017")

db = client.application

collection_user = db["user"]