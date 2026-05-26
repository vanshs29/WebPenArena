import os
import sqlite3
import uuid

from flask import Flask

from .db import get_db, init_db


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates")

    if test_config:
        app.config.update(test_config)
    else:
        app.config["DATABASE"] = os.path.join(app.instance_path, "talenthub.db")
        app.config["SCORE_TOKEN"] = os.environ.get("SCORE_TOKEN", "")
        os.makedirs(app.instance_path, exist_ok=True)

    with app.app_context():
        db = get_db(app)
        init_db(db)
        secret_row = db.execute("SELECT value FROM config WHERE key='jwt_secret'").fetchone()
        app.config["JWT_SECRET"] = secret_row["value"]
        db.close()

    from .routes import bp
    app.register_blueprint(bp)

    return app
