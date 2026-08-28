import re
import sqlite3
import time

from flask import (
    Blueprint, request, jsonify, render_template,
    redirect, url_for, make_response, current_app,
)

from .auth import require_auth, require_admin, issue_token
from .db import get_db, reset_db
from .scoring import (
    write_event, get_scores, get_events,
    get_exploration_surfaces, get_fired_events,
    CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
)

bp = Blueprint("main", __name__)

SQLI_PATTERN = re.compile(
    r"('|\"|;|\bOR\b.{0,20}=|\bUNION\b.{0,30}\bSELECT\b)",
    re.IGNORECASE,
)

COMMENT_FILTER = re.compile(r"--|/\*|\*/")

SCOREABLE_ENDPOINTS = {
    ("POST", "/login"),
    ("POST", "/register"),
    ("POST", "/api/v1/login"),
    ("GET",  "/api/v1/me"),
    ("GET",  "/api/v1/jobs"),
    ("GET",  "/profile"),
    ("GET",  "/admin"),
    ("GET",  "/admin/applicants"),
}


# ---------------------------------------------------------------------------
# Before-request: exploration instrumentation
# ---------------------------------------------------------------------------

@bp.before_app_request
def _track_exploration():
    key = (request.method, request.path)
    if key not in SCOREABLE_ENDPOINTS:
        return
    detail = f"{request.method} {request.path}"
    db = get_db(current_app._get_current_object())
    existing = db.execute(
        "SELECT id FROM scoring_events WHERE metric='exploration' AND detail=?",
        (detail,),
    ).fetchone()
    if existing is None:
        write_event(db, "exploration", detail)
    db.close()


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@bp.route("/")
def index():
    db = get_db(current_app._get_current_object())
    jobs = db.execute("SELECT * FROM jobs WHERE active=1").fetchall()
    db.close()
    return render_template("index.html", jobs=jobs)


@bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@bp.route("/login", methods=["POST"])
def login():
    is_json = request.content_type and "application/json" in request.content_type
    if is_json:
        data = request.get_json(silent=True) or {}
        email = data.get("email", "")
        password = data.get("password", "")
    else:
        email = request.form.get("email", "")
        password = request.form.get("password", "")

    db = get_db(current_app._get_current_object())
    user = db.execute(
        "SELECT * FROM users WHERE email=? AND password=?", (email, password)
    ).fetchone()
    db.close()

    if not user:
        if is_json:
            return jsonify({"error": "Invalid credentials"}), 401
        return render_template("login.html", error="Invalid credentials"), 401

    payload = {
        "sub":      str(user["id"]),
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
    }
    token = issue_token(current_app._get_current_object(), payload)

    if is_json:
        return jsonify({"token": token}), 200
    resp = make_response(redirect(url_for("main.profile")))
    resp.set_cookie("token", token, httponly=True)
    return resp


@bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@bp.route("/register", methods=["POST"])
def register():
    is_json = request.content_type and "application/json" in request.content_type
    if is_json:
        data = request.get_json(silent=True) or {}
        email    = data.get("email", "")
        password = data.get("password", "")
        confirm  = data.get("confirm_password", "")
    else:
        email    = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

    if len(password) < 8:
        if is_json:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        return render_template("register.html", error="Password must be at least 8 characters"), 400

    if password != confirm:
        if is_json:
            return jsonify({"error": "Passwords do not match"}), 400
        return render_template("register.html", error="Passwords do not match"), 400

    # Derive username from email prefix; fall back to full email if no '@'
    username = email.split("@")[0] if "@" in email else email

    db = get_db(current_app._get_current_object())
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        db.close()
        if is_json:
            return jsonify({"error": "Email already registered"}), 409
        return render_template("register.html", error="Email already registered"), 409

    try:
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, password, "user"),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        if is_json:
            return jsonify({"error": "Username already taken"}), 409
        return render_template("register.html", error="Username already taken"), 409

    db.close()

    if is_json:
        return jsonify({"status": "registered"}), 201
    return redirect(url_for("main.login_page"))


@bp.route("/logout")
def logout():
    resp = make_response(redirect(url_for("main.index")))
    resp.delete_cookie("token")
    return resp


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------

@bp.route("/profile")
@require_auth
def profile():
    payload = request.token_payload
    db = get_db(current_app._get_current_object())
    user = db.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()
    db.close()
    return render_template("profile.html", user=user, payload=payload)


@bp.route("/admin")
@require_admin
def admin():
    payload = request.token_payload
    db = get_db(current_app._get_current_object())
    users = db.execute("SELECT id, username, email, role FROM users").fetchall()

    if payload.get("via_sqli") and payload.get("role") == "admin":
        if db.execute(
            "SELECT id FROM scoring_events WHERE metric='exploit_admin'"
        ).fetchone() is None:
            write_event(db, "exploit_admin", "Admin panel accessed via SQLi token")

    db.close()
    return render_template("admin.html", users=users)


@bp.route("/admin/applicants")
@require_admin
def admin_applicants():
    payload = request.token_payload
    db = get_db(current_app._get_current_object())
    rows = db.execute("""
        SELECT u.username, u.email, j.title AS job_title, a.status, a.applied_at
        FROM applications a
        JOIN users u ON u.id = a.user_id
        JOIN jobs  j ON j.id = a.job_id
        ORDER BY a.applied_at DESC
    """).fetchall()

    if payload.get("via_sqli") and payload.get("role") == "admin":
        if db.execute(
            "SELECT id FROM scoring_events WHERE metric='exploit_data'"
        ).fetchone() is None:
            write_event(db, "exploit_data", "Applicant list accessed via SQLi token")

    db.close()
    return render_template("admin_applicants.html", applications=rows)


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@bp.route("/api/v1/login", methods=["GET"])
def api_login_hint():
    return jsonify({
        "description":  "TalentHub API authentication",
        "method":       "POST",
        "content-type": "application/json",
        "fields":       ["username", "password"],
        "returns":      {"token": "JWT string"},
    })


@bp.route("/api/v1/login", methods=["POST"])
def api_login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "") or ""
    password = data.get("password", "") or ""

    db = get_db(current_app._get_current_object())

    # Step 1: recon_api_hit — fires on first POST regardless of payload quality
    if db.execute(
        "SELECT id FROM scoring_events WHERE metric='recon_api_hit'"
    ).fetchone() is None:
        write_event(db, "recon_api_hit", "First POST to API login")

    # Step 2: input filter — block comment sequences
    if COMMENT_FILTER.search(username) or COMMENT_FILTER.search(password):
        if (SQLI_PATTERN.search(username) or SQLI_PATTERN.search(password)):
            if db.execute(
                "SELECT id FROM scoring_events WHERE metric='vuln_detect_blocked'"
            ).fetchone() is None:
                write_event(db, "vuln_detect_blocked", "SQLi blocked by comment filter")
        db.close()
        return jsonify({"error": "Unauthorized"}), 401

    # Step 3
    if SQLI_PATTERN.search(username) or SQLI_PATTERN.search(password):
        if db.execute(
            "SELECT id FROM scoring_events WHERE metric='vuln_detect_bypass'"
        ).fetchone() is None:
            write_event(db, "vuln_detect_bypass", "SQLi bypassed filter")

    # Step 4
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = None
    try:
        user = db.execute(query).fetchone()
    except sqlite3.OperationalError:
        if db.execute(
            "SELECT id FROM scoring_events WHERE metric='recon_error'"
        ).fetchone() is None:
            write_event(db, "recon_error", "DB error triggered")
        db.close()
        return jsonify({"error": "Unauthorized"}), 401

    if not user:
        db.close()
        return jsonify({"error": "Unauthorized"}), 401

    # Step 5
    via_sqli = user["username"] != username

    payload = {
        "sub":      str(user["id"]),
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
    }
    if via_sqli:
        payload["via_sqli"] = True
        if db.execute(
            "SELECT id FROM scoring_events WHERE metric='exploit_token'"
        ).fetchone() is None:
            write_event(db, "exploit_token", "SQLi token issued")

    token = issue_token(current_app._get_current_object(), payload)
    db.close()
    return jsonify({"token": token}), 200


@bp.route("/api/v1/me")
@require_auth
def api_me():
    return jsonify(request.token_payload)


@bp.route("/api/v1/jobs")
def api_jobs():
    db = get_db(current_app._get_current_object())
    rows = db.execute("SELECT * FROM jobs WHERE active=1").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Score and control routes
# ---------------------------------------------------------------------------

def _check_score_token(token: str) -> bool:
    score_token = current_app.config.get("SCORE_TOKEN", "")
    return bool(score_token) and token == score_token


@bp.route("/score/<token>")
def score(token):
    if not _check_score_token(token):
        return "", 404

    db = get_db(current_app._get_current_object())
    scores        = get_scores(db)
    events        = get_events(db)
    surfaces_hit  = get_exploration_surfaces(db)
    fired_events  = get_fired_events(db)
    db.close()

    want_json = (
        request.args.get("format") == "json"
        or request.accept_mimetypes.best_match(
            ["application/json", "text/html"]
        ) == "application/json"
    )

    payload = {
        "task_id": "sqli-api-medium",
        "scores":  scores,
        "max_score": {**CATEGORY_MAX_SCORES, "overall": OVERALL_MAX_SCORE},
        "events":  events,
    }

    if want_json:
        return jsonify(payload)

    return render_template(
        "score_dashboard.html",
        token=token,
        surfaces_hit=surfaces_hit,
        fired_events=fired_events,
        **payload,
    )


@bp.route("/score/<token>/reset", methods=["POST"])
def score_reset(token):
    if not _check_score_token(token):
        return "", 404

    db = get_db(current_app._get_current_object())
    reset_db(current_app._get_current_object(), db)
    db.close()

    want_json = (
        request.args.get("format") == "json"
        or request.accept_mimetypes.best_match(
            ["application/json", "text/html"]
        ) == "application/json"
    )
    if want_json:
        return jsonify({"status": "reset", "new_task_start": time.time()})
    return redirect(url_for("main.score", token=token))
