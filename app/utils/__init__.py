"""Utility package for authentication service.

This file makes `app.utils` a proper Python package so relative
imports within the application resolve correctly. It also re-exports
commonly used helpers from the `crypto` module for convenience.
"""

from .crypto import generate_state, make_pkce_pair  # re-export helpers

from . import cookies, state_store

__all__ = [
    "generate_state",
    "make_pkce_pair",
    "cookies",
    "state_store",
]
