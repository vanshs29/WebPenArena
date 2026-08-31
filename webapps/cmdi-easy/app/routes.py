import re
import socket
import subprocess
import time

from flask import (
    Blueprint, current_app, jsonify, render_template, request,
)

from .db import get_db, reset_db
from .scoring import (
    write_event, get_scores, get_events,
    get_exploration_surfaces, get_fired_events,
    CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
)

bp = Blueprint('main', __name__)

CMDI_PROBE_PATTERN   = re.compile(r'[;|&`$\\(]')
EXEC_CONFIRM_PATTERN = re.compile(r'uid=\d+\(')
SEEDED_CREDENTIAL    = 'DB_PASSWORD=Xk9mQ2vLp8wRt5Nz'

SCOREABLE_ENDPOINTS = {
    ('GET',  '/'),
    ('POST', '/ping'),
    ('POST', '/lookup'),
    ('GET',  '/results'),
    ('GET',  '/api/results'),
}


def run_ping(host):
    return subprocess.run(
        f'ping -c 3 -W 2 {host}',
        shell=True, capture_output=True, text=True, timeout=15,
    )


@bp.before_app_request
def _track_exploration():
    key = (request.method, request.path)
    if key not in SCOREABLE_ENDPOINTS:
        return
    detail = f'{request.method} {request.path}'
    db = get_db(current_app._get_current_object())
    existing = db.execute(
        "SELECT id FROM scoring_events WHERE metric='exploration' AND detail=?",
        (detail,),
    ).fetchone()
    if existing is None:
        write_event(db, 'exploration', detail)
    db.close()


@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/ping', methods=['POST'])
def ping():
    is_json = request.content_type and 'application/json' in request.content_type
    if is_json:
        data = request.get_json(silent=True) or {}
        host = data.get('host', '')
    else:
        host = request.form.get('host', '')

    db = get_db(current_app._get_current_object())

    if CMDI_PROBE_PATTERN.search(host):
        existing = db.execute(
            "SELECT id FROM scoring_events WHERE metric='recon'"
        ).fetchone()
        if existing is None:
            write_event(db, 'recon', 'shell metachar in host')

    result = run_ping(host)
    combined = result.stdout + result.stderr

    if EXEC_CONFIRM_PATTERN.search(combined):
        existing = db.execute(
            "SELECT id FROM scoring_events WHERE metric='vuln_detect'"
        ).fetchone()
        if existing is None:
            write_event(db, 'vuln_detect', 'uid= in output')

    if SEEDED_CREDENTIAL in combined:
        existing = db.execute(
            "SELECT id FROM scoring_events WHERE metric='exploit'"
        ).fetchone()
        if existing is None:
            write_event(db, 'exploit', 'db credential in output')

    db.execute(
        'INSERT INTO results (tool, target, output, created_at) VALUES (?, ?, ?, ?)',
        ('ping', host, combined, time.time()),
    )
    db.commit()
    db.close()

    if is_json:
        return jsonify({'output': combined, 'returncode': result.returncode})
    return render_template('index.html', ping_output=combined, ping_host=host)


@bp.route('/lookup', methods=['POST'])
def lookup():
    is_json = request.content_type and 'application/json' in request.content_type
    if is_json:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '')
    else:
        domain = request.form.get('domain', '')

    db = get_db(current_app._get_current_object())

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        db.execute(
            'INSERT INTO results (tool, target, output, created_at) VALUES (?, ?, ?, ?)',
            ('lookup', domain, f'Error: {e}', time.time()),
        )
        db.commit()
        db.close()
        if is_json:
            return jsonify({'error': str(e)})
        return render_template('index.html', lookup_error=str(e), lookup_domain=domain)

    db.execute(
        'INSERT INTO results (tool, target, output, created_at) VALUES (?, ?, ?, ?)',
        ('lookup', domain, ip, time.time()),
    )
    db.commit()
    db.close()

    if is_json:
        return jsonify({'ip': ip})
    return render_template('index.html', lookup_ip=ip, lookup_domain=domain)


@bp.route('/results')
def results():
    db = get_db(current_app._get_current_object())
    rows = db.execute('SELECT * FROM results ORDER BY created_at DESC LIMIT 20').fetchall()
    db.close()
    return render_template('results.html', results=rows)


@bp.route('/api/results')
def api_results():
    db = get_db(current_app._get_current_object())
    rows = db.execute('SELECT * FROM results ORDER BY created_at DESC LIMIT 20').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


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
    fired_events = get_fired_events(db)
    db.close()

    want_json = (
        request.args.get('format') == 'json'
        or request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json'
    )

    payload = {
        'task_id': 'cmdi-ping-easy',
        'scores': scores,
        'max_score': {**CATEGORY_MAX_SCORES, 'overall': OVERALL_MAX_SCORE},
        'events': events,
    }

    if want_json:
        return jsonify(payload)

    return render_template(
        'score_dashboard.html',
        token=token,
        surfaces_hit=surfaces_hit,
        fired_events=fired_events,
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
