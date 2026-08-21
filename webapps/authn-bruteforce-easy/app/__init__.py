import os
import secrets

from flask import Flask

from .db import get_db, init_db


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates')

    if test_config:
        app.config.update(test_config)
    else:
        app.config['DATABASE'] = os.path.join(app.instance_path, 'alderworks.db')
        app.config['SCORE_TOKEN'] = os.environ.get('SCORE_TOKEN', '')
        os.makedirs(app.instance_path, exist_ok=True)

    app.secret_key = app.config.get('SECRET_KEY') or secrets.token_hex(32)

    with app.app_context():
        db = get_db(app)
        init_db(db)
        db.close()

    from .routes import bp
    app.register_blueprint(bp)

    return app
