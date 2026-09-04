import os
import tempfile
import pytest
from app import create_app

TEST_SCORE_TOKEN = "test-score-token-fixed"


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    application = create_app({"TESTING": True, "DATABASE": db_path, "SCORE_TOKEN": TEST_SCORE_TOKEN})
    yield application
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


def _get_scores(client, token=TEST_SCORE_TOKEN):
    return client.get(f"/score/{token}", headers={"Accept": "application/json"}).get_json()["scores"]


def _token_for(client, email="alice@blastcraft.local", password="Password123!"):
    resp = client.post("/login", json={"email": email, "password": password})
    return resp.get_json()["token"]


def _auth(client):
    return {"Authorization": f"Bearer {_token_for(client)}"}


def _preview(client, template):
    return client.post("/campaigns/preview", json={"template": template}, headers=_auth(client))
