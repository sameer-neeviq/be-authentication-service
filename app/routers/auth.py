"""
Authentication routes.
"""
from typing import Optional
from fastapi import APIRouter, Request, Response, Depends, Query
from fastapi.responses import RedirectResponse

from ..models.auth import AuthStatusResponse
from ..models.responses import SuccessResponse
from ..services.auth_service import AuthService
from ..middleware.logging_config import get_logger

logger = get_logger("auth_router")
router = APIRouter(prefix="/auth", tags=["authentication"])


def get_auth_service() -> AuthService:
    """Dependency to get auth service instance."""
    return AuthService()


@router.get("/login", response_class=RedirectResponse)
async def login(
    redirect_to: Optional[str] = Query(None, description="URL to redirect to after login"),
    auth_service: AuthService = Depends(get_auth_service)
) -> RedirectResponse:
    """
    Initiate OAuth2 login flow with Cognito.
    
    - **redirect_to**: Optional URL to redirect to after successful login
    """
    logger.info("Login endpoint called")
    return await auth_service.initiate_login(redirect_to)


@router.get("/callback", response_class=RedirectResponse)
async def callback(
    code: str = Query(..., description="Authorization code from Cognito"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    response: Response = Response(),
    auth_service: AuthService = Depends(get_auth_service)
) -> RedirectResponse:
    """
    Handle OAuth2 callback from Cognito.
    
    - **code**: Authorization code from Cognito
    - **state**: State parameter for CSRF protection
    """
    logger.info("Callback endpoint called")
    return await auth_service.handle_callback(code, state, response)


@router.post("/refresh", response_model=SuccessResponse)
async def refresh(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> SuccessResponse:
    """
    Refresh access and ID tokens using refresh token from cookie.
    """
    logger.info("Refresh endpoint called")
    result = await auth_service.refresh_tokens(request, response)
    return SuccessResponse(data=result)


@router.post("/logout", response_class=RedirectResponse)
async def logout(
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> RedirectResponse:
    """
    Logout user and clear authentication cookies.
    """
    logger.info("Logout endpoint called")
    return await auth_service.logout(response)


@router.get("/me", response_model=AuthStatusResponse)
async def me(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> AuthStatusResponse:
    """
    Get current authentication status and user information.
    """
    logger.debug("Auth status endpoint called")
    return await auth_service.get_auth_status(request)
