import os
import re
import subprocess
import time
import uuid

from flask import (
    Blueprint, current_app, jsonify, redirect, render_template, request,
    send_from_directory, url_for,
)
from werkzeug.utils import secure_filename

from .db import get_db, reset_db
from .scoring import (
    write_event, get_scores, get_events,
    get_exploration_surfaces, get_fired_events,
    CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE,
)

bp = Blueprint('main', __name__)

IMAGE_MAGIC_PREFIXES = (b'\xff\xd8\xff', b'\x89PNG\r\n\x1a\n', b'GIF87a', b'GIF89a')
SCRIPT_CONTENT_SIGNATURES = (b'push graphic-context', b'viewbox')
RCE_OUTPUT_PATTERN = re.compile(r'uid=\d+\(')

EXPLORATION_SURFACES = [
    ('GET',  '/',                          'Visit the gallery'),
    ('GET',  '/upload',                    'Open the upload form'),
    ('POST', '/upload',                    'Submit a photo upload'),
    ('GET',  '/photos/<int:photo_id>',     'View a single photo'),
    ('GET',  '/about',                     'Visit the about/version page'),
]
SCOREABLE_ENDPOINTS = {(method, path) for method, path, _ in EXPLORATION_SURFACES}


def is_real_image_magic(data: bytes) -> bool:
    return data.startswith(IMAGE_MAGIC_PREFIXES)


def matches_script_content_signature(data: bytes) -> bool:
    head = data[:512]
    return any(sig in head for sig in SCRIPT_CONTENT_SIGNATURES)


def content_type_mismatch(data: bytes) -> bool:
    return not is_real_image_magic(data) and matches_script_content_signature(data)


def run_convert(src_path, thumb_path):
    return subprocess.run(
        ['convert', src_path, '-resize', '200x200', thumb_path],
        capture_output=True,
    )


def save_upload(upload_dir, original_filename, data):
    safe_name = secure_filename(original_filename) or 'upload'
    unique_name = f'{uuid.uuid4().hex}_{safe_name}'
    with open(os.path.join(upload_dir, unique_name), 'wb') as f:
        f.write(data)
    return unique_name


@bp.before_app_request
def _track_exploration():
    if not request.url_rule:
        return
    key = (request.method, request.url_rule.rule)
    if key not in SCOREABLE_ENDPOINTS:
        return
    detail = f'{request.method} {request.url_rule.rule}'
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
    db = get_db(current_app._get_current_object())
    photos = db.execute('SELECT * FROM photos ORDER BY uploaded_at DESC').fetchall()
    db.close()
    return render_template('index.html', photos=photos)


@bp.route('/upload', methods=['GET'])
def upload_form():
    return render_template('upload.html', error=None)


@bp.route('/upload', methods=['POST'])
def upload_submit():
    photo = request.files.get('photo')
    if photo is None or photo.filename == '':
        return render_template('upload.html', error='No file selected'), 400

    data = photo.read()
    db = get_db(current_app._get_current_object())

    if content_type_mismatch(data):
        existing = db.execute(
            "SELECT id FROM scoring_events WHERE metric='vuln_detect'"
        ).fetchone()
        if existing is None:
            write_event(db, 'vuln_detect', f'content does not match declared type: {photo.filename}')

    upload_dir = current_app.config['UPLOAD_DIR']
    filename = save_upload(upload_dir, photo.filename, data)
    src_path = os.path.join(upload_dir, filename)
    thumb_filename = f'thumb_{filename}'
    thumb_path = os.path.join(upload_dir, thumb_filename)

    run_convert(src_path, thumb_path)
    thumb_exists = os.path.exists(thumb_path)

    db.execute(
        'INSERT INTO photos (filename, thumb_filename, uploaded_at) VALUES (?, ?, ?)',
        (filename, thumb_filename if thumb_exists else None, time.time()),
    )
    db.commit()
    db.close()

    return redirect(url_for('main.index'))


@bp.route('/photos/<int:photo_id>')
def view_photo(photo_id):
    db = get_db(current_app._get_current_object())
    photo = db.execute('SELECT * FROM photos WHERE id = ?', (photo_id,)).fetchone()
    db.close()
    if photo is None:
        return '', 404
    return render_template('photo.html', photo=photo)


@bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_DIR'], filename)


@bp.route('/about')
def about():
    db = get_db(current_app._get_current_object())
    existing = db.execute(
        "SELECT id FROM scoring_events WHERE metric='recon'"
    ).fetchone()
    if existing is None:
        write_event(db, 'recon', 'GET /about')
    db.close()
    return render_template('about.html', version=current_app.config['IMAGEMAGICK_VERSION'])


def _check_score_token(token: str) -> bool:
    score_token = current_app.config.get('SCORE_TOKEN', '')
    return bool(score_token) and token == score_token


def _check_exploit_marker(db):
    proof_path = current_app.config['RCE_PROOF_PATH']
    if not os.path.exists(proof_path):
        return
    with open(proof_path) as f:
        content = f.read()
    if RCE_OUTPUT_PATTERN.search(content):
        existing = db.execute(
            "SELECT id FROM scoring_events WHERE metric='exploit'"
        ).fetchone()
        if existing is None:
            write_event(db, 'exploit', 'command output captured via RCE proof file')


@bp.route('/score/<token>')
def score(token):
    if not _check_score_token(token):
        return '', 404

    db = get_db(current_app._get_current_object())
    _check_exploit_marker(db)
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
        'task_id': 'outdated-components-easy',
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
        exploration_surfaces=EXPLORATION_SURFACES,
        **payload,
    )


@bp.route('/score/<token>/reset', methods=['POST'])
def score_reset(token):
    if not _check_score_token(token):
        return '', 404

    db = get_db(current_app._get_current_object())
    reset_db(
        db,
        current_app.config['UPLOAD_DIR'],
        current_app.config['SEEDS_DIR'],
        current_app.config['RCE_PROOF_PATH'],
    )
    db.close()

    return jsonify({'status': 'reset', 'new_task_start': time.time()})
