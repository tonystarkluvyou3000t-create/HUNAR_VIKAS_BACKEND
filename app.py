"""PLACEHOLDER feature app. Same hook as the real one: create_app(config, identity_resolver)."""
from urllib.parse import urlparse

from flask import Flask, jsonify, request, redirect


def create_app(config=None, identity_resolver=None):
    if identity_resolver is None:
        raise RuntimeError("identity_resolver is required (no development identity)")
    app = Flask(__name__)
    app.config.update(config or {})

    @app.get("/")
    def root_redirect():
        target = app.config.get("APP_BASE_URL") or "https://hunarvikas.live"
        return redirect(target, code=302)

    @app.before_request
    def write_guard():  # same-origin JSON guard, as the contract describes
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("Origin")
            allowed_origins = app.config.get("ALLOWED_ORIGINS", ())
            same_origin = origin and urlparse(origin).netloc == request.host
            configured_origin = origin and origin.rstrip("/") in allowed_origins
            if origin and not (same_origin or configured_origin):
                return jsonify(error="cross-origin write rejected"), 403
            if not request.is_json:
                return jsonify(error="JSON required"), 415

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/session")
    def session():
        ident = identity_resolver()
        return jsonify(
            authenticated=bool(ident),
            dev_mode=False,
            role=ident["role"] if ident else None,
            approved=bool(ident and ident["approved"]),
            activities=[],
            goals=[],
        )

    return app