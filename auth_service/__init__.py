"""Hunar Vikas authentication service.

    auth = AuthService.from_env()
    app = create_app({"DEV_MODE": False}, identity_resolver=auth.resolve_identity)
    auth.init_app(app)
"""
from .config import AuthConfig
from .service import AuthError, AuthService, SessionInfo

__all__ = ["AuthConfig", "AuthService", "AuthError", "SessionInfo"]
