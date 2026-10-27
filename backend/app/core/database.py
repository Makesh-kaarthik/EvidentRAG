from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.core.config import settings


client = None
database = None


def connect_to_mongodb():
    global client, database

    try:
        client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=5000,
        )

        # Force a connection test
        client.admin.command("ping")

        database = client[settings.mongodb_database]

        print("========================================")
        print("MongoDB Connection: SUCCESS")
        print(f"Database: {settings.mongodb_database}")
        print("========================================")

        return database

    except PyMongoError as error:
        print("========================================")
        print("MongoDB Connection: FAILED")
        print(f"Error: {error}")
        print("========================================")

        client = None
        database = None

        raise


def close_mongodb_connection():
    global client

    if client:
        client.close()
        print("MongoDB connection closed.")


def get_database():
    if database is None:
        raise RuntimeError("MongoDB database is not connected.")

    return database