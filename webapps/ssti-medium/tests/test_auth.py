from app.db import get_db


def test_register_creates_account(client):
    resp = client.post("/register", json={"email": "carol@blastcraft.local", "password": "Secure1!"})
    assert resp.status_code in (200, 201)


def test_password_is_hashed_not_plaintext(client, app):
    client.post("/register", json={"email": "dave@blastcraft.local", "password": "Secure1!"})
    with app.app_context():
        row = get_db(app).execute(
            "SELECT password_hash FROM users WHERE email=?", ("dave@blastcraft.local",)
        ).fetchone()
        assert row["password_hash"] != "Secure1!"
        assert row["password_hash"].startswith("$2b$")


def test_login_with_seed_credentials_succeeds(client):
    resp = client.post("/login", json={"email": "alice@blastcraft.local", "password": "Password123!"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_login_wrong_password_fails(client):
    resp = client.post("/login", json={"email": "alice@blastcraft.local", "password": "wrong"})
    assert resp.status_code == 401


def test_preview_requires_auth(client):
    resp = client.post("/campaigns/preview", json={"template": "hi"})
    assert resp.status_code == 401
