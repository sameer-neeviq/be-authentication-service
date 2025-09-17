"""
Common response models.
"""
from typing import Optional, Dict, Any
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str
    details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseModel):
    """Standard success response model."""
    success: bool = True
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = "healthy"
    version: Optional[str] = None
    timestamp: Optional[str] = None
