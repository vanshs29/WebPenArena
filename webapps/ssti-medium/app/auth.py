from functools import wraps

import jwt as pyjwt
from flask import current_app, jsonify, request


def issue_token(app, payload: dict) -> str:
    return pyjwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")


def _decode_token(app, token: str) -> dict | None:
    try:
        return pyjwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
    except pyjwt.PyJWTError:
        return None


def _get_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw = _get_token_from_request()
        if not raw:
            return jsonify({"error": "Authentication required"}), 401
        payload = _decode_token(current_app._get_current_object(), raw)
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.token_payload = payload
        return f(*args, **kwargs)

    return decorated
