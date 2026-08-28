import os
import subprocess

from flask import Flask

from .db import get_db, init_db

SEEDS_DIR = os.path.join(os.path.dirname(__file__), 'seeds')


def _detect_imagemagick_version():
    try:
        result = subprocess.run(
            ['convert', '-version'], capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.splitlines()
        return lines[0] if lines else 'unknown'
    except Exception:
        return 'unknown'


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates')

    if test_config:
        app.config.update(test_config)
    else:
        app.config['DATABASE'] = os.path.join(app.instance_path, 'pixsnap.db')
        app.config['SCORE_TOKEN'] = os.environ.get('SCORE_TOKEN', '')
        app.config['UPLOAD_DIR'] = os.path.join(app.instance_path, 'uploads')
        app.config['RCE_PROOF_PATH'] = os.environ.get(
            'RCE_PROOF_PATH', os.path.join(app.config['UPLOAD_DIR'], '.rce-proof'),
        )
        os.makedirs(app.instance_path, exist_ok=True)
        os.makedirs(app.config['UPLOAD_DIR'], exist_ok=True)

    app.config.setdefault('SEEDS_DIR', SEEDS_DIR)
    app.config['IMAGEMAGICK_VERSION'] = _detect_imagemagick_version()

    with app.app_context():
        db = get_db(app)
        init_db(db, app.config['UPLOAD_DIR'], app.config['SEEDS_DIR'])
        db.close()

    from .routes import bp
    app.register_blueprint(bp)

    return app
