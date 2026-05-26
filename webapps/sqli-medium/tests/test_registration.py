import pytest
from conftest import _user_token


def test_register_new_user_json(client):
    resp = client.post("/register", json={
        "email": "charlie@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code in (200, 201, 302)


def test_register_duplicate_email_fails(client):
    client.post("/register", json={
        "email": "dup@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    resp = client.post("/register", json={
        "email": "dup@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code == 409


def test_register_password_too_short(client):
    resp = client.post("/register", json={
        "email": "x@talenthub.local",
        "password": "short",
        "confirm_password": "short",
    })
    assert resp.status_code == 400


def test_register_password_mismatch(client):
    resp = client.post("/register", json={
        "email": "x@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "Different1",
    })
    assert resp.status_code == 400


def test_register_role_always_user(client):
    client.post("/register", json={
        "email": "fake@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
        "role": "admin",
    })
    token = _user_token(client, "fake@talenthub.local", "SecurePass1")
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_register_parameterised_no_500(client):
    resp = client.post("/register", json={
        "email": "' OR '1'='1' --",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code != 500
