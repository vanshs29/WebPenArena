from conftest import _auth


def test_create_campaign_succeeds(client):
    resp = client.post(
        "/campaigns", json={"subject": "Hello", "body": "Hi {{contact.first_name}}"}, headers=_auth(client)
    )
    assert resp.status_code in (200, 201)


def test_create_campaign_does_not_render_body(client):
    resp = client.post(
        "/campaigns", json={"subject": "Test", "body": "{{7*7}}"}, headers=_auth(client)
    )
    assert resp.status_code in (200, 201)
    listing = client.get("/campaigns", headers=_auth(client))
    assert b"{{7*7}}" in listing.data or b"49" not in listing.data


def test_create_campaign_requires_auth(client):
    resp = client.post("/campaigns", json={"subject": "s", "body": "b"})
    assert resp.status_code == 401
