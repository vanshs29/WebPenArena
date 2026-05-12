def test_sqli_bypass_succeeds(client):
    resp = client.post("/login", json={"email": "' OR '1'='1' --", "password": "x"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_sqli_token_grants_admin_access(client):
    token = client.post("/login", json={
        "email": "' OR '1'='1' --", "password": "x"
    }).get_json()["token"]
    resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert b"admin@shoplite.local" in resp.data


def test_admin_requires_auth(client):
    assert client.get("/admin").status_code == 401


def test_admin_rejects_regular_user_token(client):
    token = client.post("/login", json={
        "email": "user@shoplite.local", "password": "password123"
    }).get_json()["token"]
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_profile_requires_auth(client):
    assert client.get("/profile").status_code == 401
