"""
Authentication routes.
"""
from typing import Optional
from fastapi import APIRouter, Request, Response, \
    HTTPException, status, Depends, Query
from fastapi.responses import RedirectResponse
from ..models.responses import SuccessResponse
from ..services.auth_service import AuthService
from ..middleware.logging_config import get_logger
from ..models.auth import ResendRequest, AuthStatusResponse, \
    SignupRequest, ConfirmSignupRequest, LoginRequest, \
    ResendRequest, ForgotPasswordRequest, \
    ResetPasswordRequest, ChangePasswordRequest

logger = get_logger("auth_router")
router = APIRouter(prefix="/auth", tags=["authentication"])


def get_auth_service() -> AuthService:
    """Dependency to get auth service instance."""
    return AuthService()


@router.post("/signup", response_model=dict)
async def signup_post(
    signup: SignupRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Create a new user in the Cognito user pool using email + password.
    """
    try:
        signup.validate_passwords()
        result = await auth_service.signup_user(signup.email, signup.password)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        # boto3 ClientError
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        # Fallback: try to parse from string
        if not user_msg:
            msg = str(e)
            # If message contains ':', take the part after the last ':'
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        # logger.error(f"Signup failed: {user_msg}")
        return {"success": False, "error": user_msg}


@router.post("/confirm", response_model=dict)
async def confirm_signup(
    confirm: ConfirmSignupRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Confirm a Cognito signup using the confirmation code delivered to the user.
    """
    try:
        result = await auth_service.confirm_signup(confirm.email, confirm.confirmation_code)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}



@router.post("/login", response_model=dict)
async def login(
    login: LoginRequest,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Authenticate user with email and password (server-side) and set auth cookies.
    """
    try:
        result = await auth_service.login_user(login.email, login.password, response)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}


@router.get("/me", response_model=AuthStatusResponse)
async def me(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> AuthStatusResponse:
    """
    Get current authentication status and user information.
    Using the Access Token from the cookie.
    """
    return await auth_service.get_auth_status(request)


@router.post("/refresh", response_model=SuccessResponse)
async def refresh(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
) -> SuccessResponse:
    """
    Refresh access and ID tokens using refresh token from cookie.
    """
    try:
        result = await auth_service.refresh_tokens(request, response)
        return SuccessResponse(data=result)
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return SuccessResponse(data={"success": False, "error": user_msg})


@router.post("/logout", response_class=RedirectResponse)
async def logout(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
) -> RedirectResponse:
    """
    Logout user and clear authentication cookies.
    """
    return await auth_service.logout(request, response)


@router.post("/resend", response_model=dict)
async def resend_confirmation(
    req: ResendRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Resend signup confirmation code to user's email."""
    try:
        result = await auth_service.resend_confirmation_code(req.email)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}
    
@router.post("/forgot-password", response_model=dict)
async def forgot_password(
    req: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Send a password reset code to user's email."""
    try:
        result = await auth_service.forgot_password(req.email)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}

@router.post("/reset-password", response_model=dict)
async def reset_password(
    req: ResetPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Reset password using code sent to email."""
    try:
        result = await auth_service.reset_password(req.email, req.code, req.new_password)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}

@router.post("/change-password", response_model=dict)
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Change password for authenticated user."""
    try:
        result = await auth_service.change_password(request, req.old_password, req.new_password)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}
    
@router.post("/logout-all", response_model=dict)
async def logout_all(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """Log out user from all devices (global sign-out)."""
    try:
        result = await auth_service.logout_all(request)
        return {"success": True, "result": result}
    except Exception as e:
        user_msg = None
        if hasattr(e, "response") and hasattr(e, "operation_name"):
            error_msg = e.response["Error"].get("Message")
            if error_msg:
                user_msg = error_msg
        if not user_msg:
            msg = str(e)
            if ":" in msg:
                user_msg = msg.split(":")[-1].strip()
            else:
                user_msg = msg
        return {"success": False, "error": user_msg}
