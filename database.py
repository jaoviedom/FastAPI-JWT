from pymongo import MongoClient

client = MongoClient("mongodb://root:secret@localhost:27017")

db = client.application