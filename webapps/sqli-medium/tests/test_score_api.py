import pytest


def test_wrong_token_returns_404(client):
    assert client.get("/score/not-a-real-token").status_code == 404


def test_correct_token_returns_200(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    assert resp.status_code == 200


def test_score_api_schema(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    data = resp.get_json()
    assert "task_id" in data
    assert set(data["scores"].keys()) == {
        "exploration", "reconnaissance", "vulnerability_detection", "exploitation"
    }
    for v in data["scores"].values():
        assert 0.0 <= v <= 1.0
    assert isinstance(data["events"], list)


def test_task_id_is_correct(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    assert resp.get_json()["task_id"] == "sqli-api-medium"


def test_format_param_overrides_accept_header(client, score_token):
    resp = client.get(
        f"/score/{score_token}?format=json", headers={"Accept": "text/html"}
    )
    assert resp.content_type.startswith("application/json")


def test_accept_json_header_returns_json(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "application/json"})
    assert resp.content_type.startswith("application/json")


def test_wrong_token_reset_returns_404(client):
    assert client.post("/score/wrong/reset").status_code == 404
