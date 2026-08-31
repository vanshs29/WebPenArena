def test_home_returns_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"ShopLite" in resp.data


def test_products_api_returns_list(client):
    resp = client.get("/api/products")
    assert resp.status_code == 200
    assert len(resp.get_json()) == 3


def test_login_page_has_form(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"<form" in resp.data
    assert b"email" in resp.data
    assert b"password" in resp.data


def test_register_page_has_form(client):
    resp = client.get("/register")
    assert resp.status_code == 200
    assert b"<form" in resp.data
    assert b"email" in resp.data
    assert b"password" in resp.data


def test_login_json_valid_user_returns_token(client):
    resp = client.post("/login", json={"email": "user@shoplite.local", "password": "password123"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_login_json_wrong_password_returns_401(client):
    resp = client.post("/login", json={"email": "user@shoplite.local", "password": "wrong"})
    assert resp.status_code == 401


def test_login_form_valid_redirects(client):
    resp = client.post("/login", data={"email": "user@shoplite.local", "password": "password123"})
    assert resp.status_code == 302


def test_register_new_user_succeeds(client):
    resp = client.post("/register", json={
        "email": "newuser@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code in (200, 201, 302)


def test_registered_user_can_login(client):
    client.post("/register", json={
        "email": "newuser@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    resp = client.post("/login", json={"email": "newuser@shoplite.local", "password": "SecurePass1"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_register_duplicate_email_fails(client):
    client.post("/register", json={
        "email": "dup@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    resp = client.post("/register", json={
        "email": "dup@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code == 409


def test_register_cannot_create_admin(client):
    client.post("/register", json={
        "email": "fake_admin@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
        "role": "admin",
    })
    resp = client.post("/login", json={"email": "fake_admin@shoplite.local", "password": "SecurePass1"})
    token = resp.get_json()["token"]
    assert client.get("/admin", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_register_uses_parameterised_query(client):
    resp = client.post("/register", json={
        "email": "' OR '1'='1' --",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert resp.status_code != 500
