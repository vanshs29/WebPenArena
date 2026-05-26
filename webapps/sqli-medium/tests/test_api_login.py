import pytest


def test_api_login_valid_credentials(client):
    resp = client.post("/api/v1/login", json={
        "username": "alice", "password": "password123"
    })
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_api_login_jwt_contains_username(client):
    import jwt as pyjwt
    token = client.post("/api/v1/login", json={
        "username": "alice", "password": "password123"
    }).get_json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload["username"] == "alice"
    assert "email" in payload
    assert payload["role"] == "user"
    assert isinstance(payload["sub"], str)


def test_api_login_no_via_sqli_for_normal_login(client):
    import jwt as pyjwt
    token = client.post("/api/v1/login", json={
        "username": "alice", "password": "password123"
    }).get_json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert "via_sqli" not in payload


def test_api_login_wrong_password(client):
    resp = client.post("/api/v1/login", json={
        "username": "alice", "password": "wrong"
    })
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Unauthorized"


def test_api_login_nonexistent_user(client):
    resp = client.post("/api/v1/login", json={
        "username": "nobody", "password": "password123"
    })
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Unauthorized"


def test_api_login_empty_body(client):
    resp = client.post("/api/v1/login", json={})
    assert resp.status_code == 401
