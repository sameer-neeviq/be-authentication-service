"""Lightweight AWS clients using boto3 for this project.

This module provides a tiny wrapper around boto3 for common Cognito
administrative operations. It intentionally keeps interfaces small and
uses the project's `settings` for configuration.
"""
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..config.settings import settings
from ..middleware.logging_config import LoggerMixin
import hmac
import hashlib
import base64


class AWSClient(LoggerMixin):
    """Encapsulates boto3 clients needed by the service."""

    def __init__(self, region_name: Optional[str] = None):
        self.region = region_name or settings.cognito_region
        self._boto_session = boto3.session.Session(region_name=self.region)
        self.client_secret = settings.cognito_app_client_secret

    def cognito_idp_client(self):
        """Return a boto3 Cognito Identity Provider client.

        The client will pick up AWS credentials from the environment,
        shared credentials file (~/.aws/credentials), or IAM role when
        running in AWS.
        """
        return self._boto_session.client('cognito-idp')

    def admin_get_user(self, username: str, user_pool_id: Optional[str] = None) -> Dict[str, Any]:
        """Get a user from Cognito User Pool using admin API.

        Inputs:
        - username: the username to look up
        - user_pool_id: optional override, defaults to settings.cognito_user_pool_id

        Returns the response dict from Cognito. Raises RuntimeError on failure.
        """
        pool_id = user_pool_id or settings.cognito_user_pool_id
        client = self.cognito_idp_client()
        try:
            self.logger.info(f"Fetching Cognito user {username} from pool {pool_id}")
            resp = client.admin_get_user(UserPoolId=pool_id, Username=username)
            return resp
        except ClientError as e:
            self.logger.error(f"Cognito client error: {e}")
            raise RuntimeError(f"Cognito admin_get_user failed: {e}")
        except BotoCoreError as e:
            self.logger.error(f"Boto core error: {e}")
            raise RuntimeError(f"AWS error: {e}")

    def sign_up(self, username: str, password: str, user_attributes: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Register a new user with Cognito User Pool using the public SignUp API.

        - username: usually the email for the user
        - password: plaintext password to register (Cognito validates complexity)
        - user_attributes: dict of additional attributes (e.g., {'email': 'user@example.com'})

        Returns the raw response from Cognito or raises RuntimeError on failure.
        """
        client = self.cognito_idp_client()
        attrs = []
        if user_attributes:
            attrs = [{'Name': k, 'Value': v} for k, v in user_attributes.items()]

        try:
            self.logger.info(f"Signing up user {username}")
            params = {
                'ClientId': settings.cognito_app_client_id,
                'Username': username,
                'Password': password,
                'UserAttributes': attrs
            }

            # If the app client has a secret, compute SECRET_HASH
            if settings.cognito_app_client_secret:
                message = (username + settings.cognito_app_client_id).encode('utf-8')
                dig = hmac.new(settings.cognito_app_client_secret.encode('utf-8'), message, hashlib.sha256).digest()
                secret_hash = base64.b64encode(dig).decode()
                params['SecretHash'] = secret_hash

            resp = client.sign_up(**params)
            return resp
        except ClientError as e:
            self.logger.error(f"Cognito sign_up error: {e}")
            raise RuntimeError(f"Cognito sign_up failed: {e}")
        except BotoCoreError as e:
            self.logger.error(f"Boto core error during sign_up: {e}")
            raise RuntimeError(f"AWS error: {e}")

    def confirm_sign_up(self, username: str, confirmation_code: str) -> Dict[str, Any]:
        """Confirm a user's signup using the confirmation code sent by Cognito."""
        client = self.cognito_idp_client()
        try:
            params = {
                'ClientId': settings.cognito_app_client_id,
                'Username': username,
                'ConfirmationCode': confirmation_code
            }

            if settings.cognito_app_client_secret:
                message = (username + settings.cognito_app_client_id).encode('utf-8')
                dig = hmac.new(settings.cognito_app_client_secret.encode('utf-8'), message, hashlib.sha256).digest()
                secret_hash = base64.b64encode(dig).decode()
                params['SecretHash'] = secret_hash

            resp = client.confirm_sign_up(**params)
            return resp
        except ClientError as e:
            self.logger.error(f"Cognito confirm_sign_up error: {e}")
            raise RuntimeError(f"Cognito confirm_sign_up failed: {e}")
        except BotoCoreError as e:
            self.logger.error(f"Boto core error during confirm_sign_up: {e}")
            raise RuntimeError(f"AWS error: {e}")

    def initiate_auth(self, username: str, password: str) -> Dict[str, Any]:
        """Initiate USER_PASSWORD_AUTH flow to authenticate a user.

        Returns the AuthenticationResult dict containing tokens on success.
        """
        client = self.cognito_idp_client()
        try:
            params = {
                'ClientId': settings.cognito_app_client_id,
                'AuthFlow': 'USER_PASSWORD_AUTH',
                'AuthParameters': {
                    'USERNAME': username,
                    'PASSWORD': password
                }
            }

            # If app client has secret, include SECRET_HASH in AuthParameters
            if settings.cognito_app_client_secret:
                message = (username + settings.cognito_app_client_id).encode('utf-8')
                dig = hmac.new(settings.cognito_app_client_secret.encode('utf-8'), message, hashlib.sha256).digest()
                secret_hash = base64.b64encode(dig).decode()
                params['AuthParameters']['SECRET_HASH'] = secret_hash

            resp = client.initiate_auth(**params)
            # return AuthenticationResult which holds tokens
            return resp.get('AuthenticationResult', {})
        except ClientError as e:
            self.logger.error(f"Cognito initiate_auth error: {e}")
            raise RuntimeError(f"Cognito initiate_auth failed: {e}")
        except BotoCoreError as e:
            self.logger.error(f"Boto core error during initiate_auth: {e}")
            raise RuntimeError(f"AWS error: {e}")
        
    
    def refresh_auth(self, refresh_token: str, username: str) -> dict:
        """
        Use REFRESH_TOKEN_AUTH to get new AccessToken (and often IdToken).
        If your app client has a secret, 'username' is required to compute SECRET_HASH.
        """
        client = self.cognito_idp_client()

        params = {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": settings.cognito_app_client_id,
            "AuthParameters": {
                "REFRESH_TOKEN": refresh_token,
            },
        }

        # Compute SECRET_HASH if we have a client secret (same pattern as your other methods)
        if settings.cognito_app_client_secret and username:
            message = (username + settings.cognito_app_client_id).encode('utf-8')
            dig = hmac.new(settings.cognito_app_client_secret.encode('utf-8'), message, hashlib.sha256).digest()
            secret_hash = base64.b64encode(dig).decode()
            params["AuthParameters"]["SECRET_HASH"] = secret_hash

        resp = client.initiate_auth(**params)
        return resp.get("AuthenticationResult", {})
    