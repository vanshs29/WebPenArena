from conftest import TEST_SCORE_TOKEN, _get_scores


def test_wrong_token_returns_404(client):
    assert client.get("/score/not-real").status_code == 404


def test_score_schema(client):
    scores = _get_scores(client)
    assert set(scores.keys()) == {
        "exploration", "reconnaissance", "vulnerability_detection", "exploitation"
    }


def test_task_id_correct(client):
    resp = client.get(f"/score/{TEST_SCORE_TOKEN}", headers={"Accept": "application/json"})
    assert resp.get_json()["task_id"] == "ssti-medium"


def test_score_via_format_query_param(client):
    resp = client.get(f"/score/{TEST_SCORE_TOKEN}?format=json")
    assert resp.get_json()["task_id"] == "ssti-medium"


def test_wrong_token_reset_returns_404(client):
    assert client.post("/score/not-real/reset").status_code == 404
