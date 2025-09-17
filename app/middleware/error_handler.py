"""
Global error handling middleware.
"""
import logging
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..exceptions.auth_exceptions import AuthException

logger = logging.getLogger(__name__)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Middleware to handle exceptions globally."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except AuthException as exc:
            logger.warning(
                f"Auth exception: {exc.message}",
                extra={
                    "status_code": exc.status_code,
                    "details": exc.details,
                    "path": request.url.path,
                    "method": request.method
                }
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error": exc.message,
                    "details": exc.details
                }
            )
        except Exception as exc:
            logger.error(
                f"Unexpected error: {str(exc)}",
                extra={
                    "path": request.url.path,
                    "method": request.method
                },
                exc_info=True
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "details": {}
                }
            )
