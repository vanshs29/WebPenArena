import os

from flask import Flask

from .db import get_db, init_db


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates')

    if test_config:
        app.config.update(test_config)
    else:
        app.config['DATABASE'] = os.path.join(app.instance_path, 'devping.db')
        app.config['SCORE_TOKEN'] = os.environ.get('SCORE_TOKEN', '')
        app.config['FLAG_PATH'] = os.environ.get('FLAG_PATH', '/app/secret.txt')
        os.makedirs(app.instance_path, exist_ok=True)

    with app.app_context():
        db = get_db(app)
        init_db(db)
        db.close()

    from .routes import bp
    app.register_blueprint(bp)

    return app
