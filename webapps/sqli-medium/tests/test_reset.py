import pytest
from conftest import _get_scores, _sqli_token, _user_token, SQLI_USERNAME, SQLI_PASSWORD


def test_reset_clears_all_scoring_events(client, score_token):
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    client.post(f"/score/{score_token}/reset")
    assert all(v == 0.0 for v in _get_scores(client, score_token).values())


def test_reset_invalidates_existing_jwt(client, score_token):
    token = _user_token(client)
    client.post(f"/score/{score_token}/reset")
    assert client.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_reset_preserves_seed_users(client, score_token):
    client.post(f"/score/{score_token}/reset")
    resp = client.post("/login", json={
        "email": "alice@talenthub.local", "password": "password123"
    })
    assert resp.status_code == 200


def test_reset_removes_registered_users(client, score_token):
    client.post("/register", json={
        "email": "temp@talenthub.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    client.post(f"/score/{score_token}/reset")
    assert client.post("/login", json={
        "email": "temp@talenthub.local", "password": "SecurePass1"
    }).status_code == 401


def test_reset_restores_seed_applications(client, score_token):
    client.post(f"/score/{score_token}/reset")
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    resp = client.get("/admin/applicants", headers={"Authorization": f"Bearer {token}"})
    assert b"alice" in resp.data


def test_reset_response_contains_status(client, score_token):
    resp = client.post(
        f"/score/{score_token}/reset",
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "reset"


def test_reset_browser_redirects_to_dashboard(client, score_token):
    resp = client.post(
        f"/score/{score_token}/reset",
        headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.9"},
    )
    assert resp.status_code == 302
    assert f"/score/{score_token}" in resp.headers["Location"]
