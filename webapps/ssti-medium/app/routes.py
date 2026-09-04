import time

import bcrypt
from flask import (
    Blueprint, current_app, jsonify, redirect, render_template,
    render_template_string, request, url_for,
)

from .auth import issue_token, require_auth
from .db import SAMPLE_CONTACT, get_db, reset_db
from .filtering import contains_disallowed_pattern, matches_bypass_signature
from .scoring import (
    check_exploitation_signals, check_expr_evaluated, get_events,
    get_exploration_surfaces, get_fired_events, get_scores, write_event_once,
)

bp = Blueprint("main", __name__)


@bp.before_app_request
def _track_exploration():
    from .scoring import EXPLORATION_SURFACES, write_event

    detail = f"{request.method} {request.path}"
    if detail not in EXPLORATION_SURFACES:
        return
    db = get_db(current_app._get_current_object())
    existing = db.execute(
        "SELECT id FROM scoring_events WHERE metric='exploration' AND detail=?", (detail,)
    ).fetchone()
    if existing is None:
        write_event(db, "exploration", detail)
    db.close()


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")

    db = get_db(current_app._get_current_object())
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    token = issue_token(current_app._get_current_object(), {"sub": str(user["id"]), "email": user["email"]})
    return jsonify({"token": token}), 200


@bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    db = get_db(current_app._get_current_object())
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        db.close()
        return jsonify({"error": "Email already registered"}), 409

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash)
    )
    db.commit()
    db.close()
    return jsonify({"status": "registered"}), 201


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------

@bp.route("/contacts")
@require_auth
def contacts():
    db = get_db(current_app._get_current_object())
    rows = db.execute("SELECT * FROM contacts").fetchall()
    db.close()
    return render_template("contacts.html", contacts=rows)


@bp.route("/campaigns")
@require_auth
def campaigns():
    payload = request.token_payload
    db = get_db(current_app._get_current_object())
    rows = db.execute(
        "SELECT * FROM campaigns WHERE owner_id=? ORDER BY created_at DESC", (payload["sub"],)
    ).fetchall()
    db.close()
    return render_template("campaigns.html", campaigns=rows)


@bp.route("/campaigns/new")
@require_auth
def campaigns_new():
    return render_template("campaignNew.html")


@bp.route("/campaigns", methods=["POST"])
@require_auth
def campaigns_create():
    payload = request.token_payload
    data = request.get_json(silent=True) or {}
    subject = data.get("subject", "")
    body = data.get("body", "")

    db = get_db(current_app._get_current_object())
    db.execute(
        "INSERT INTO campaigns (owner_id, subject, body, created_at) VALUES (?, ?, ?, ?)",
        (payload["sub"], subject, body, time.time()),
    )
    db.commit()
    db.close()
    return jsonify({"status": "created"}), 201


@bp.route("/campaigns/preview", methods=["POST"])
@require_auth
def preview_campaign():
    data = request.get_json(silent=True) or {}
    template_text = data.get("template", "")
    if not template_text:
        return jsonify({"error": "template is required"}), 400

    db = get_db(current_app._get_current_object())
    write_event_once(db, "recon_preview_probed", "Preview requested")

    if contains_disallowed_pattern(template_text):
        write_event_once(db, "vuln_detect_blocked", "Disallowed pattern in template")
        db.close()
        return jsonify({"error": "Template contains disallowed content"}), 400

    if matches_bypass_signature(template_text):
        write_event_once(db, "vuln_detect_bypass", "attr()-based bypass signature")

    try:
        rendered = render_template_string(template_text, contact=SAMPLE_CONTACT)
    except Exception as exc:
        db.close()
        return jsonify({"rendered": None, "error": str(exc)}), 200

    check_expr_evaluated(db, template_text, rendered)
    check_exploitation_signals(db, rendered)
    db.close()
    return jsonify({"rendered": rendered}), 200


# ---------------------------------------------------------------------------
# Score and control routes
# ---------------------------------------------------------------------------

def _check_score_token(token: str) -> bool:
    score_token = current_app.config.get("SCORE_TOKEN", "")
    return bool(score_token) and token == score_token


def _wants_json() -> bool:
    return (
        request.args.get("format") == "json"
        or request.accept_mimetypes.best_match(["application/json", "text/html"]) == "application/json"
    )


@bp.route("/score/<token>")
def score(token):
    if not _check_score_token(token):
        return "", 404

    db = get_db(current_app._get_current_object())
    scores = get_scores(db)
    events = get_events(db)
    surfaces_hit = get_exploration_surfaces(db)
    fired_events = get_fired_events(db)
    db.close()

    payload = {
        "task_id": "ssti-medium",
        "scores": scores,
        "events": events,
    }

    if _wants_json():
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

    if _wants_json():
        return jsonify({"status": "reset", "new_task_start": time.time()})
    return redirect(url_for("main.score", token=token))
