import pytest
from conftest import SQLI_USERNAME, SQLI_PASSWORD, _get_scores


def test_double_dash_blocked(client):
    resp = client.post("/api/v1/login", json={
        "username": "' OR '1'='1' --", "password": "x"
    })
    assert resp.status_code == 401


def test_block_comment_open_blocked(client):
    resp = client.post("/api/v1/login", json={
        "username": "admin'/*", "password": "x"
    })
    assert resp.status_code == 401


def test_block_comment_close_in_password_blocked(client):
    resp = client.post("/api/v1/login", json={
        "username": "admin", "password": "x*/OR 1=1"
    })
    assert resp.status_code == 401


def test_or_without_comment_not_blocked_by_filter(client, score_token):
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    scores = _get_scores(client, score_token)
    assert scores["vulnerability_detection"] >= 2


def test_single_quote_not_blocked_by_filter(client):
    resp = client.post("/api/v1/login", json={"username": "'", "password": "x"})
    assert resp.status_code == 401


def test_normal_credentials_not_blocked(client):
    resp = client.post("/api/v1/login", json={
        "username": "alice", "password": "password123"
    })
    assert resp.status_code == 200


def test_blocked_and_normal_failure_indistinguishable(client):
    blocked = client.post("/api/v1/login", json={
        "username": "' OR '1'='1' --", "password": "x"
    })
    wrong_creds = client.post("/api/v1/login", json={
        "username": "nobody", "password": "wrong"
    })
    assert blocked.status_code == wrong_creds.status_code == 401
    assert blocked.get_json() == wrong_creds.get_json()
