def test_home_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"BlastCraft" in resp.data


def test_login_page_has_form(client):
    assert b"<form" in client.get("/login").data


def test_register_page_has_form(client):
    assert b"<form" in client.get("/register").data
