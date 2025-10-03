"""
Cookie management utilities.
"""
from typing import Optional
from fastapi import Response

from ..config.settings import settings
from ..middleware.logging_config import LoggerMixin


class CookieManager(LoggerMixin):
    """Manages HTTP cookies for authentication tokens."""
    
    ACCESS_COOKIE = "access_token"
    REFRESH_COOKIE = "refresh_token"
    ID_COOKIE = "id_token"
    USERNAME_COOKIE = "username"
    
    def set_cookie(
        self,
        response: Response,
        name: str,
        value: str,
        max_age: int,
        path: str = "/"
    ) -> None:
        """Set a secure HTTP-only cookie."""
        self.logger.debug(f"Setting cookie: {name}")
        
        response.set_cookie(
            name,
            value,
            httponly=True,
            secure=settings.secure_cookies,
            samesite="lax",
            max_age=max_age,
            domain=settings.cookie_domain,
            path=path
        )
    
    def clear_cookie(
        self,
        response: Response,
        name: str,
        path: str = "/"
    ) -> None:
        """Clear a cookie."""
        self.logger.debug(f"Clearing cookie: {name}")
        
        response.delete_cookie(
            name,
            domain=settings.cookie_domain,
            path=path
        )
    
    def set_auth_cookies(
        self,
        response: Response,
        access_token: str,
        id_token: Optional[str] = None,
        refresh_token: Optional[str] = None
    ) -> None:
        """Set all authentication cookies."""
        self.set_cookie(
            response,
            self.ACCESS_COOKIE,
            access_token,
            settings.access_token_ttl_seconds
        )
        
        if id_token:
            self.set_cookie(
                response,
                self.ID_COOKIE,
                id_token,
                settings.access_token_ttl_seconds
            )
        
        if refresh_token:
            self.set_cookie(
                response,
                self.REFRESH_COOKIE,
                refresh_token,
                settings.refresh_token_ttl_seconds,
                path="/auth/"
            )
    
    def clear_auth_cookies(self, response: Response) -> None:
        """Clear all authentication cookies."""
        self.clear_cookie(response, self.ACCESS_COOKIE)
        self.clear_cookie(response, self.ID_COOKIE)
        self.clear_cookie(response, self.REFRESH_COOKIE, path="/auth/")
