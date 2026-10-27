"""Check the MongoDB URI loaded from the backend .env without printing secrets."""

from pymongo import MongoClient
from pymongo.errors import (
    ConfigurationError,
    OperationFailure,
    PyMongoError,
    ServerSelectionTimeoutError,
)

try:
    from app.core.config import settings
except Exception as exc:
    print("MongoDB check: FAILED")
    print(f"Configuration could not be loaded ({type(exc).__name__}).")
    raise SystemExit(2)

client = None
try:
    client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=12000)
    result = client.admin.command("ping")
    if result.get("ok") == 1:
        print("MongoDB check: SUCCESS")
        print(f"Database configured: {settings.mongodb_database}")
    else:
        print("MongoDB check: FAILED (server returned no successful ping).")
        raise SystemExit(1)
except ConfigurationError:
    print("MongoDB check: FAILED")
    print("URI/hostname configuration or DNS lookup failed; verify MONGODB_URI in .env.")
    raise SystemExit(2)
except ServerSelectionTimeoutError:
    print("MongoDB check: FAILED")
    print("Could not reach the configured cluster before timeout; check network access and cluster availability.")
    raise SystemExit(2)
except OperationFailure:
    print("MongoDB check: FAILED")
    print("The server rejected authentication or authorization; verify database credentials and permissions.")
    raise SystemExit(2)
except PyMongoError as exc:
    print("MongoDB check: FAILED")
    print(f"Database driver error ({type(exc).__name__}); URI and credentials were not displayed.")
    raise SystemExit(2)
finally:
    if client is not None:
        client.close()
