"""
Auth BFF - Backend for Frontend Authentication Service
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config.settings import settings
from .middleware.error_handler import ErrorHandlerMiddleware
from .middleware.logging_config import setup_logging, get_logger
from .routers import auth, health
from .utils.state_store import state_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    setup_logging()
    logger = get_logger("main")
    logger.info("Starting Auth service")

    yield

    # Shutdown
    logger.info("Shutting down Auth service")


app = FastAPI(
    title=settings.app_name,
    description="Backend Authentication Service with AWS Cognito",
    version="1.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(ErrorHandlerMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(health.router)
