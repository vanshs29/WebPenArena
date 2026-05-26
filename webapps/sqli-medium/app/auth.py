import jwt as pyjwt
from functools import wraps
from flask import request, jsonify, current_app


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
    return request.cookies.get("token")


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


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw = _get_token_from_request()
        if not raw:
            return jsonify({"error": "Authentication required"}), 401
        payload = _decode_token(current_app._get_current_object(), raw)
        if payload is None:
            return jsonify({"error": "Invalid or expired token"}), 401
        if payload.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        request.token_payload = payload
        return f(*args, **kwargs)
    return decorated
