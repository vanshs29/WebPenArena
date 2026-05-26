import pytest
from conftest import _user_token, _sqli_token


# Cycle 1 — App skeleton and job listings

def test_home_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"TalentHub" in resp.data


def test_home_shows_job_listings(client):
    resp = client.get("/")
    assert b"Software Engineer" in resp.data


def test_api_jobs_returns_list(client):
    resp = client.get("/api/v1/jobs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 3


def test_login_page_has_form(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"<form" in resp.data
    assert b"email" in resp.data


def test_register_page_has_form(client):
    resp = client.get("/register")
    assert resp.status_code == 200
    assert b"<form" in resp.data


def test_api_login_get_returns_hint(client):
    resp = client.get("/api/v1/login")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "fields" in data
    assert "username" in data["fields"]
    assert "password" in data["fields"]


# Cycle 7 — Auth decorators

def test_profile_requires_auth(client):
    assert client.get("/profile").status_code == 401


def test_profile_with_user_token(client):
    token = _user_token(client)
    assert client.get("/profile", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_admin_requires_auth(client):
    assert client.get("/admin").status_code == 401


def test_admin_rejects_user_token(client):
    token = _user_token(client)
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_admin_accepts_admin_token(client):
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_admin_applicants_requires_admin(client):
    token = _user_token(client)
    assert client.get("/admin/applicants", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_api_me_requires_auth(client):
    assert client.get("/api/v1/me").status_code == 401


def test_api_me_returns_payload(client):
    token = _user_token(client)
    resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_token_in_cookie_accepted(client):
    client.post("/login", data={
        "email": "alice@talenthub.local", "password": "password123"
    })
    assert client.get("/profile").status_code == 200


# Cycle 8 — Admin and applicants routes content

def test_admin_shows_user_list(client):
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert b"alice" in resp.data
    assert b"bob" in resp.data


def test_admin_applicants_shows_applications(client):
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    resp = client.get("/admin/applicants", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert b"alice" in resp.data


def test_profile_shows_current_user_data(client):
    token = _user_token(client)
    resp = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert b"alice" in resp.data


def test_logout_clears_cookie(client):
    client.post("/login", data={
        "email": "alice@talenthub.local", "password": "password123"
    })
    client.get("/logout")
    assert client.get("/profile").status_code == 401
