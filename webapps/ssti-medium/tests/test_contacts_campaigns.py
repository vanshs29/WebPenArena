from conftest import _auth


def test_contacts_lists_seed_rows(client):
    resp = client.get("/contacts", headers=_auth(client))
    assert b"Jordan" in resp.data and b"Priya" in resp.data and b"Sam" in resp.data


def test_campaigns_starts_empty(client):
    resp = client.get("/campaigns", headers=_auth(client))
    assert resp.status_code == 200


def test_campaigns_requires_auth(client):
    assert client.get("/campaigns").status_code == 401


def test_contacts_requires_auth(client):
    assert client.get("/contacts").status_code == 401


def test_campaigns_new_page_requires_auth(client):
    assert client.get("/campaigns/new").status_code == 401


def test_campaigns_new_page_renders_for_member(client):
    resp = client.get("/campaigns/new", headers=_auth(client))
    assert resp.status_code == 200
