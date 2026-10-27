import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.core.database import close_mongodb_connection, connect_to_mongodb


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await asyncio.to_thread(connect_to_mongodb)
    try:
        yield
    finally:
        await asyncio.to_thread(close_mongodb_connection)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Evidence-aware cybersecurity Retrieval-Augmented Generation API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "message": "Cyber EvidentRAG API is running",
        "version": settings.app_version,
        "status": "ready",
    }


app.include_router(router, prefix="/api")
