"""HTTP layer: /api/auth/* routes, CSRF protection and cookie handling."""
from __future__ import annotations

from urllib.parse import urlparse

from flask import Blueprint, Flask, jsonify, request

from .security import constant_time_equals
from .service import AuthError, AuthService

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_BODY = 16 * 1024
# Pre-session endpoints: no authenticated cookie state to protect yet.
CSRF_EXEMPT = {
    "/api/auth/register", "/api/auth/verify-email", "/api/auth/resend-verification",
    "/api/auth/login", "/api/auth/forgot-password", "/api/auth/reset-password",
}


def _json_body() -> dict:
    if not request.is_json:
        raise AuthError(415, "unsupported_media_type", "A JSON request body is required.")
    if (request.content_length or 0) > MAX_BODY:
        raise AuthError(413, "payload_too_large", "Request body too large.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise AuthError(400, "invalid_json", "Request body must be a JSON object.")
    return data


def _respond(payload: dict, status: int = 200):
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _client_key() -> str:
    # Behind a proxy, configure werkzeug ProxyFix so remote_addr is the real client.
    return request.remote_addr or "unknown"


def build_blueprint(svc: AuthService) -> Blueprint:
    bp = Blueprint("hv_auth", __name__, url_prefix="/api/auth")
    cfg = svc.cfg

    def set_session_cookie(resp, token: str, remember: bool):
        resp.set_cookie(
            cfg.cookie_name, token,
            max_age=cfg.remember_absolute_seconds if remember else None,  # None = browser-session cookie
            httponly=True, secure=cfg.cookie_secure, samesite=cfg.cookie_samesite, path="/",
        )

    def clear_session_cookie(resp):
        resp.delete_cookie(
            cfg.cookie_name, httponly=True, secure=cfg.cookie_secure,
            samesite=cfg.cookie_samesite, path="/")

    @bp.post("/register")
    def register():
        return _respond(svc.register(_json_body(), _client_key()), 202)

    @bp.post("/resend-verification")
    def resend_verification():
        return _respond(svc.resend_verification(_json_body().get("email"), _client_key()), 202)

    @bp.post("/verify-email")
    def verify_email():
        data = _json_body()
        remember = data.get("remember") is True
        token, info = svc.verify_email(data, _client_key(), remember)
        resp = _respond(svc.session_payload(info))
        set_session_cookie(resp, token, remember)
        return resp

    @bp.post("/login")
    def login():
        data = _json_body()
        token, info = svc.login(data, _client_key())
        resp = _respond(svc.session_payload(info))
        set_session_cookie(resp, token, data.get("remember") is True)
        return resp

    @bp.post("/logout")
    def logout():
        info = svc.current_session()
        if info:
            svc.revoke_session(info.session_hash)
        resp = _respond({"ok": True})
        clear_session_cookie(resp)
        return resp

    @bp.post("/logout-all")
    def logout_all():
        info = svc.current_session()
        if info:
            svc.revoke_all_sessions(info.user_id)
        resp = _respond({"ok": True})
        clear_session_cookie(resp)
        return resp

    @bp.get("/me")
    def me():
        info = svc.current_session()
        if info is None:
            return _respond({"authenticated": False})
        return _respond(svc.session_payload(info))

    @bp.post("/forgot-password")
    def forgot_password():
        return _respond(svc.forgot_password(_json_body().get("email"), _client_key()), 202)

    @bp.post("/reset-password")
    def reset_password():
        resp = _respond(svc.reset_password(_json_body(), _client_key()))
        clear_session_cookie(resp)  # the caller must sign in again
        return resp

    return bp


def init_app(app: Flask, svc: AuthService) -> None:
    """Mount the auth routes and protections on the feature app.

    Call after create_app(...). Registered hooks run after the feature app's
    own JSON/Origin write guard, which still applies to every route.
    """
    if app.config.get("DEV_MODE") and svc.cfg.environment == "production":
        raise RuntimeError("Refusing to start: DEV_MODE must be False in production.")

    @app.before_request
    def _origin_and_csrf_guard():
        if request.method in SAFE_METHODS:
            return None
        origin = request.headers.get("Origin")
        allowed_origins = svc.cfg.allowed_origins
        same_origin = origin and urlparse(origin).netloc == request.host
        configured_origin = origin and origin.rstrip("/") in allowed_origins
        if origin and not (same_origin or configured_origin):
            return _respond({"error": "Cross-origin request rejected.", "code": "bad_origin"}, 403)
        if request.path.rstrip("/") in CSRF_EXEMPT:
            return None
        if not request.cookies.get(svc.cfg.cookie_name):
            return None  # no cookie auth in play; protected routes will answer 401
        info = svc.current_session()
        if info is None:
            return None  # stale cookie: not authenticated, nothing to forge
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not constant_time_equals(sent, svc.csrf_for(info)):
            return _respond({"error": "Missing or invalid CSRF token.", "code": "csrf_failed"}, 403)
        return None

    @app.errorhandler(AuthError)
    def _auth_error(err: AuthError):
        body = {"error": err.message, "code": err.code}
        if err.fields:
            body["fields"] = err.fields
        resp = _respond(body, err.status)
        for key, value in err.headers.items():
            resp.headers[key] = value
        return resp

    app.register_blueprint(build_blueprint(svc))
