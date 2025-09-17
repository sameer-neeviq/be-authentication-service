"""
Health check routes.
"""
from datetime import datetime
from fastapi import APIRouter

from ..models.responses import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat()
    )


@router.get("/", response_model=HealthResponse)
async def root() -> HealthResponse:
    """
    Root endpoint - returns health status.
    """
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat()
    )
