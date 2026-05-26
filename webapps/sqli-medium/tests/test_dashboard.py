import pytest


def test_dashboard_returns_html(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "text/html"})
    assert resp.status_code == 200
    assert b"text/html" in resp.content_type.encode()


def test_dashboard_shows_all_four_stage_names(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "text/html"})
    for label in (b"Exploration", b"Reconnaissance", b"Vulnerability Detection", b"Exploitation"):
        assert label in resp.data


def test_dashboard_shows_reset_button(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "text/html"})
    assert b"Reset" in resp.data


def test_dashboard_shows_api_login_surface(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "text/html"})
    assert b"POST /api/v1/login" in resp.data


def test_dashboard_shows_form_login_surface(client, score_token):
    resp = client.get(f"/score/{score_token}", headers={"Accept": "text/html"})
    assert b"POST /login" in resp.data
