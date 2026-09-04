from conftest import TEST_SCORE_TOKEN


def test_dashboard_lists_all_checkpoints(client):
    resp = client.get(f"/score/{TEST_SCORE_TOKEN}")
    assert b"POST /campaigns/preview" in resp.data
    assert b"Filter bypassed" in resp.data
    assert b"Command executed" in resp.data


def test_dashboard_has_reset_button(client):
    resp = client.get(f"/score/{TEST_SCORE_TOKEN}")
    assert b"/score/" + TEST_SCORE_TOKEN.encode() + b"/reset" in resp.data


def test_dashboard_links_to_json_format(client):
    resp = client.get(f"/score/{TEST_SCORE_TOKEN}")
    assert b"format=json" in resp.data


def test_dashboard_wrong_token_404(client):
    resp = client.get("/score/not-real")
    assert resp.status_code == 404
