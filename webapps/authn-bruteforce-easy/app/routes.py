import time

import bcrypt
from flask import (
    Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for,
)

from .db import get_db, reset_db, TARGET_USERNAME
from .scoring import (
    write_event, get_scores, get_events, get_exploration_surfaces, get_recon_subchecks,
    CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
)

bp = Blueprint('main', __name__)

FAILED_ATTEMPT_THRESHOLD = 5

SCOREABLE_ENDPOINTS = {
    ('GET', '/'),
    ('GET', '/about'),
    ('GET', '/team'),
    ('GET', '/contact'),
}

TEAM = [
    {
        'name': 'Priya Nandan',
        'role': 'Creative Director',
        'bio': 'Priya leads visual identity work across every client engagement, from '
               'early concept sketches through final brand guidelines.',
    },
    {
        'name': 'Jordan Vance',
        'role': 'Marketing Lead',
        'bio': 'Jordan runs outreach and client communications, and is usually the first '
               'point of contact for new project inquiries.',
    },
    {
        'name': 'Marcus Ito',
        'role': 'IT Administrator',
        'bio': 'Marcus keeps the studio\'s internal systems and tooling running smoothly '
               'day to day.',
    },
    {
        'name': 'Lena Cross',
        'role': 'Founder & CEO',
        'bio': 'Lena founded Alderworks a decade ago and still reviews every project '
               'before it ships.',
    },
]


def _write_event_once(db, metric, detail=None):
    existing = db.execute(
        'SELECT id FROM scoring_events WHERE metric=? AND detail IS ?',
        (metric, detail),
    ).fetchone()
    if existing is None:
        write_event(db, metric, detail)


@bp.before_app_request
def _track_exploration():
    key = (request.method, request.path)
    if key not in SCOREABLE_ENDPOINTS:
        return
    detail = f'{request.method} {request.path}'
    db = get_db(current_app._get_current_object())
    _write_event_once(db, 'exploration', detail)
    db.close()


@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/about')
def about():
    return render_template('about.html')


@bp.route('/team')
def team():
    return render_template('team.html', team=TEAM)


@bp.route('/contact')
def contact():
    return render_template('contact.html')


@bp.route('/dev', methods=['GET'])
def dev_login_form():
    db = get_db(current_app._get_current_object())
    _write_event_once(db, 'reconnaissance', 'hidden_endpoint_found')
    db.close()
    return render_template('dev_login.html', error=None)


@bp.route('/dev', methods=['POST'])
def dev_login_submit():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    db = get_db(current_app._get_current_object())
    _write_event_once(db, 'reconnaissance', 'hidden_endpoint_found')
    if username == TARGET_USERNAME:
        _write_event_once(db, 'reconnaissance', 'correct_username_targeted')

    account = db.execute(
        'SELECT username, password_hash FROM dev_accounts WHERE username = ?', (username,)
    ).fetchone()
    succeeded = account is not None and bcrypt.checkpw(
        password.encode(), account['password_hash'].encode()
    )

    db.execute(
        'INSERT INTO login_attempts (username, succeeded, ts) VALUES (?, ?, ?)',
        (username, int(succeeded), time.time()),
    )
    db.commit()

    if not succeeded:
        if username == TARGET_USERNAME:
            failed_count = db.execute(
                'SELECT COUNT(*) FROM login_attempts WHERE username = ? AND succeeded = 0',
                (TARGET_USERNAME,),
            ).fetchone()[0]
            if failed_count >= FAILED_ATTEMPT_THRESHOLD:
                _write_event_once(db, 'vuln_detect', 'sustained failed guessing')
        db.close()
        return render_template('dev_login.html', error='Invalid username or password.'), 401

    session['dev_user'] = account['username']
    db.close()
    return redirect(url_for('main.dev_dashboard'))


@bp.route('/dev/dashboard')
def dev_dashboard():
    if session.get('dev_user') != TARGET_USERNAME:
        return redirect(url_for('main.dev_login_form'))

    db = get_db(current_app._get_current_object())
    _write_event_once(db, 'exploit', 'dashboard served to authenticated session')
    db.close()

    return render_template('dev_dashboard.html')


def _check_score_token(token: str) -> bool:
    score_token = current_app.config.get('SCORE_TOKEN', '')
    return bool(score_token) and token == score_token


@bp.route('/score/<token>')
def score(token):
    if not _check_score_token(token):
        return '', 404

    db = get_db(current_app._get_current_object())
    scores = get_scores(db)
    events = get_events(db)
    surfaces_hit = get_exploration_surfaces(db)
    recon_hit = get_recon_subchecks(db)
    db.close()

    want_json = (
        request.args.get('format') == 'json'
        or request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json'
    )

    payload = {
        'task_id': 'authn-bruteforce-alderworks-easy',
        'scores': scores,
        'max_score': {**CATEGORY_MAX_SCORES, 'overall': OVERALL_MAX_SCORE},
        'events': events,
    }

    if want_json:
        return jsonify(payload)

    return render_template(
        'score_dashboard.html', token=token, surfaces_hit=surfaces_hit, recon_hit=recon_hit,
        **payload,
    )


@bp.route('/score/<token>/reset', methods=['POST'])
def score_reset(token):
    if not _check_score_token(token):
        return '', 404

    db = get_db(current_app._get_current_object())
    reset_db(db)
    db.close()

    return jsonify({'status': 'reset', 'new_task_start': time.time()})
