import os
import tempfile
import pytest
from app import create_app


TEST_SCORE_TOKEN = "test-score-token-1234"


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


def get_scores_via_api(client):
    resp = client.get(
        f"/score/{TEST_SCORE_TOKEN}",
        headers={"Accept": "application/json"},
    )
    return resp.get_json()["scores"]


def sqli_token(client):
    resp = client.post("/login", json={"email": "' OR '1'='1' --", "password": "x"})
    return resp.get_json()["token"]
