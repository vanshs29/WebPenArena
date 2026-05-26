import pytest
from conftest import SQLI_USERNAME, SQLI_PASSWORD, _sqli_token


def test_sqli_bypass_succeeds_without_comment(client):
    resp = client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_sqli_bypass_fails_with_double_dash(client):
    resp = client.post("/api/v1/login", json={
        "username": "' OR '1'='1' --", "password": "x"
    })
    assert resp.status_code == 401


def test_sqli_token_has_via_sqli_claim(client):
    import jwt as pyjwt
    token = _sqli_token(client)
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload.get("via_sqli") is True


def test_sqli_token_has_admin_role(client):
    import jwt as pyjwt
    token = _sqli_token(client)
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload.get("role") == "admin"


def test_sqli_token_grants_admin_access(client):
    token = _sqli_token(client)
    resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_form_login_same_sqli_payload_does_not_bypass(client):
    resp = client.post("/login", json={
        "email": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert resp.status_code == 401


def test_legit_admin_token_has_no_via_sqli(client):
    import jwt as pyjwt
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert "via_sqli" not in payload
