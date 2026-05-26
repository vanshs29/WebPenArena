import os
import tempfile
import pytest
from app import create_app

TEST_SCORE_TOKEN = "test-score-token-fixed"
SQLI_USERNAME = "' OR '1'='1"
SQLI_PASSWORD = "' OR '1'='1"


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    application = create_app({
        "TESTING": True,
        "DATABASE": db_path,
        "SCORE_TOKEN": TEST_SCORE_TOKEN,
    })
    yield application
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def score_token():
    return TEST_SCORE_TOKEN


def _get_scores(client, score_token):
    return client.get(
        f"/score/{score_token}", headers={"Accept": "application/json"}
    ).get_json()["scores"]


def _sqli_token(client):
    """Return a JWT obtained via SQLi bypass (via_sqli: True, role: admin)."""
    return client.post(
        "/api/v1/login", json={"username": SQLI_USERNAME, "password": SQLI_PASSWORD}
    ).get_json()["token"]


def _user_token(client, email="alice@talenthub.local", password="password123"):
    """Return a normal user JWT via the safe form login."""
    return client.post(
        "/login", json={"email": email, "password": password}
    ).get_json()["token"]
