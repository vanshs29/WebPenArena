from app.scoring import CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE


def test_wrong_token_returns_404(client):
    assert client.get("/score/not-a-real-token").status_code == 404


def test_score_api_returns_correct_schema(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "task_id" in data
    assert set(data["scores"].keys()) == {
        "exploration", "reconnaissance", "vulnerability_detection", "exploitation"
    }
    for category, v in data["scores"].items():
        assert 0.0 <= v <= CATEGORY_MAX_SCORES[category]
    assert isinstance(data["events"], list)


def test_score_api_format_param_overrides_accept(client, score_token):
    resp = client.get(
        f"/score/{score_token}?format=json",
        headers={"Accept": "text/html"},
    )
    assert resp.content_type.startswith("application/json")


def test_score_no_token_env_returns_404(client):
    # Wrong token always returns 404 regardless
    assert client.get("/score/wrong").status_code == 404


def test_max_score_present_and_matches_category_maxes(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    data = resp.get_json()
    assert "max_score" in data
    for category, max_value in CATEGORY_MAX_SCORES.items():
        assert data["max_score"][category] == max_value


def test_max_score_includes_overall(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    assert resp.get_json()["max_score"]["overall"] == OVERALL_MAX_SCORE
