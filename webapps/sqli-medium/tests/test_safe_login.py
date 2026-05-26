import pytest
from conftest import _get_scores, _user_token


def test_form_login_valid_credentials_json(client):
    resp = client.post("/login", json={
        "email": "alice@talenthub.local", "password": "password123"
    })
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_form_login_wrong_password(client):
    resp = client.post("/login", json={
        "email": "alice@talenthub.local", "password": "wrong"
    })
    assert resp.status_code == 401


def test_form_login_nonexistent_user(client):
    resp = client.post("/login", json={
        "email": "nobody@talenthub.local", "password": "password123"
    })
    assert resp.status_code == 401


def test_form_login_sqli_bypass_fails(client):
    resp = client.post("/login", json={
        "email": "' OR '1'='1' --", "password": "x"
    })
    assert resp.status_code == 401


def test_form_login_sqli_does_not_trigger_recon_error(client, score_token):
    client.post("/login", json={"email": "'", "password": "x"})
    assert _get_scores(client, score_token)["reconnaissance"] == 0.0


def test_form_login_no_via_sqli_claim(client):
    import jwt as pyjwt
    token = _user_token(client)
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert "via_sqli" not in payload


def test_form_login_form_submission_sets_cookie_and_redirects(client):
    resp = client.post("/login", data={
        "email": "alice@talenthub.local", "password": "password123"
    })
    assert resp.status_code == 302
    assert "token" in resp.headers.get("Set-Cookie", "")
