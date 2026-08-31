from tests.conftest import get_scores_via_api


def test_reset_clears_scoring_events(client, score_token):
    client.post("/login", json={"email": "' OR '1'='1' --", "password": "x"})
    client.post(f"/score/{score_token}/reset")
    scores = get_scores_via_api(client)
    assert all(v == 0.0 for v in scores.values())


def test_reset_invalidates_existing_jwt(client, score_token):
    token = client.post("/login", json={
        "email": "user@shoplite.local", "password": "password123"
    }).get_json()["token"]
    client.post(f"/score/{score_token}/reset")
    resp = client.get("/profile", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_reset_preserves_seed_users(client, score_token):
    client.post(f"/score/{score_token}/reset")
    resp = client.post("/login", json={"email": "user@shoplite.local", "password": "password123"})
    assert resp.status_code == 200


def test_reset_removes_registered_users(client, score_token):
    client.post("/register", json={
        "email": "registered@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    client.post(f"/score/{score_token}/reset")
    resp = client.post("/login", json={"email": "registered@shoplite.local", "password": "SecurePass1"})
    assert resp.status_code == 401


def test_reset_response_is_json(client, score_token):
    resp = client.post(f"/score/{score_token}/reset")
    assert resp.status_code == 200
    assert "status" in resp.get_json()
