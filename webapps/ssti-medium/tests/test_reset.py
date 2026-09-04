from conftest import TEST_SCORE_TOKEN, _get_scores, _preview, _token_for
from test_vuln import RCE_PAYLOAD


def test_reset_clears_all_scoring_events(client):
    _preview(client, RCE_PAYLOAD)
    client.post(f"/score/{TEST_SCORE_TOKEN}/reset")
    assert all(v == 0 for v in _get_scores(client).values())


def test_reset_invalidates_existing_jwt(client):
    token = _token_for(client)
    client.post(f"/score/{TEST_SCORE_TOKEN}/reset")
    resp = client.get("/campaigns", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_reset_preserves_seed_users(client):
    client.post(f"/score/{TEST_SCORE_TOKEN}/reset")
    resp = client.post("/login", json={"email": "alice@blastcraft.local", "password": "Password123!"})
    assert resp.status_code == 200


def test_reset_wrong_token_404(client):
    resp = client.post("/score/not-real/reset")
    assert resp.status_code == 404
