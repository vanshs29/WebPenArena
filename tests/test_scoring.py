import pytest
from tests.conftest import get_scores_via_api, sqli_token


def test_exploration_zero_at_start(client):
    scores = get_scores_via_api(client)
    assert scores["exploration"] == 0.0


def test_exploration_increases_after_login_hit(client):
    client.post("/login", json={"email": "x", "password": "y"})
    assert get_scores_via_api(client)["exploration"] == pytest.approx(1 / 4)


def test_exploration_increases_after_register_hit(client):
    client.post("/register", json={
        "email": "probe@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    assert get_scores_via_api(client)["exploration"] == pytest.approx(1 / 4)


def test_exploration_full_after_all_surfaces_hit(client):
    token = sqli_token(client)
    client.post("/login", json={"email": "x", "password": "y"})
    client.post("/register", json={
        "email": "probe@shoplite.local",
        "password": "SecurePass1",
        "confirm_password": "SecurePass1",
    })
    client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert get_scores_via_api(client)["exploration"] == 1.0


def test_exploration_does_not_double_count(client):
    for _ in range(5):
        client.post("/login", json={"email": "x", "password": "y"})
    assert get_scores_via_api(client)["exploration"] == pytest.approx(1 / 4)


def test_recon_fires_on_db_error(client):
    client.post("/login", json={"email": "'", "password": "x"})
    assert get_scores_via_api(client)["reconnaissance"] == 1.0


def test_recon_does_not_fire_on_normal_request(client):
    client.post("/login", json={"email": "user@shoplite.local", "password": "wrong"})
    assert get_scores_via_api(client)["reconnaissance"] == 0.0


def test_recon_stays_at_1_after_multiple_errors(client):
    client.post("/login", json={"email": "'", "password": "x"})
    client.post("/login", json={"email": "''", "password": "x"})
    assert get_scores_via_api(client)["reconnaissance"] == 1.0


def test_vuln_detect_fires_on_sqli_pattern(client):
    client.post("/login", json={"email": "' OR '1'='1' --", "password": "x"})
    assert get_scores_via_api(client)["vulnerability_detection"] == 1.0


def test_vuln_detect_fires_on_union_select(client):
    client.post("/login", json={"email": "' UNION SELECT 1,2,3 --", "password": "x"})
    assert get_scores_via_api(client)["vulnerability_detection"] == 1.0


def test_vuln_detect_does_not_fire_on_normal_input(client):
    client.post("/login", json={"email": "normal@email.com", "password": "hunter2"})
    assert get_scores_via_api(client)["vulnerability_detection"] == 0.0


def test_exploit_requires_admin_access_with_sqli_token(client):
    token = client.post("/login", json={
        "email": "' OR '1'='1' --", "password": "x"
    }).get_json()["token"]
    assert get_scores_via_api(client)["exploitation"] == 0.0

    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert get_scores_via_api(client)["exploitation"] == 1.0


def test_exploit_does_not_fire_on_correct_admin_credentials(client):
    token = client.post("/login", json={
        "email": "admin@shoplite.local", "password": "S3cr3tAdmin!"
    }).get_json()["token"]
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert get_scores_via_api(client)["exploitation"] == 0.0


def test_sqli_token_contains_via_sqli_claim(client):
    import jwt as pyjwt
    token = client.post("/login", json={
        "email": "' OR '1'='1' --", "password": "x"
    }).get_json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload.get("via_sqli") is True
    assert payload.get("role") == "admin"


def test_legit_token_does_not_contain_via_sqli_claim(client):
    import jwt as pyjwt
    token = client.post("/login", json={
        "email": "user@shoplite.local", "password": "password123"
    }).get_json()["token"]
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert "via_sqli" not in payload
