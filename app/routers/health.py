"""
Health check routes.
"""
from datetime import datetime
from fastapi import APIRouter

from ..models.responses import HealthResponse

router = APIRouter(tags=["health"])

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
