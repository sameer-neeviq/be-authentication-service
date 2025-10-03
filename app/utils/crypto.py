"""Cryptographic utilities for PKCE and other security operations.

This module holds the helpers previously located at `app/utils.py`.
"""
import base64
import os
import hashlib
from typing import Callable

from ..models.auth import PKCEPair


def b64url(data: bytes) -> str:
    """Encode bytes as base64url (RFC 4648 Section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_pkce_pair() -> PKCEPair:
    """Generate PKCE verifier and challenge pair."""
    verifier = b64url(os.urandom(64))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return PKCEPair(verifier=verifier, challenge=challenge)


def generate_state() -> str:
    """Generate a secure random state parameter."""
    return b64url(os.urandom(24))
