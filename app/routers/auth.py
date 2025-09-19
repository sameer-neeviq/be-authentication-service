"""
Authentication routes.
"""
from typing import Optional
from fastapi import APIRouter, Request, Response, Depends, Query
from fastapi.responses import RedirectResponse

from ..models.auth import AuthStatusResponse
from ..models.auth import SignupRequest
from ..models.responses import SuccessResponse
from ..services.auth_service import AuthService
from ..models.auth import ConfirmSignupRequest
from ..models.auth import LoginRequest
from ..middleware.logging_config import get_logger

logger = get_logger("auth_router")
router = APIRouter(prefix="/auth", tags=["authentication"])


def get_auth_service() -> AuthService:
    """Dependency to get auth service instance."""
    return AuthService()


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
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> RedirectResponse:
    """
    Logout user and clear authentication cookies.
    """
    logger.info("Logout endpoint called")
    return await auth_service.logout(request, response)


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


@router.post("/signup", response_model=dict)
async def signup_post(
    signup: SignupRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Create a new user in the Cognito user pool using email + password.
    """
    logger.info("Signup POST endpoint called")
    # Validate passwords
    signup.validate_passwords()
    result = await auth_service.signup_user(signup.email, signup.password)
    return {"success": True, "result": result}


@router.post("/confirm", response_model=dict)
async def confirm_signup(
    confirm: ConfirmSignupRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Confirm a Cognito signup using the confirmation code delivered to the user.
    """
    logger.info("Confirm signup endpoint called")
    result = await auth_service.confirm_signup(confirm.email, confirm.confirmation_code)
    return {"success": True, "result": result}



@router.post("/login", response_model=dict)
async def login(
    login: LoginRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Authenticate user with email and password (server-side) and set auth cookies.
    """
    logger.info("Login POST endpoint called")
    result = await auth_service.login_user(login.email, login.password, response)
    return {"success": True, "result": result}
