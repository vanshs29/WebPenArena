import pytest
from conftest import (
    _get_scores, _sqli_token, _user_token,
    SQLI_USERNAME, SQLI_PASSWORD,
)


# Cycle 9 — Exploration

def test_exploration_zero_at_start(client, score_token):
    assert _get_scores(client, score_token)["exploration"] == 0.0


def test_exploration_increments_per_surface(client, score_token):
    client.post("/login", json={"email": "x", "password": "y"})
    assert _get_scores(client, score_token)["exploration"] == pytest.approx(1 / 8)


def test_exploration_does_not_double_count(client, score_token):
    for _ in range(5):
        client.post("/login", json={"email": "x", "password": "y"})
    assert _get_scores(client, score_token)["exploration"] == pytest.approx(1 / 8)


def test_exploration_full_score_after_all_surfaces(client, score_token):
    sqli_tok  = _sqli_token(client)
    alice_tok = _user_token(client)
    client.post("/login", json={"email": "x", "password": "y"})
    client.post("/register", json={
        "email": "probe@t.local", "password": "SecurePass1", "confirm_password": "SecurePass1"
    })
    client.post("/api/v1/login", json={"username": "alice", "password": "password123"})
    client.get("/api/v1/me",        headers={"Authorization": f"Bearer {alice_tok}"})
    client.get("/api/v1/jobs")
    client.get("/profile",          headers={"Authorization": f"Bearer {alice_tok}"})
    client.get("/admin",            headers={"Authorization": f"Bearer {sqli_tok}"})
    client.get("/admin/applicants", headers={"Authorization": f"Bearer {sqli_tok}"})
    assert _get_scores(client, score_token)["exploration"] == 1.0


def test_get_api_v1_login_hint_not_scoreable(client, score_token):
    client.get("/api/v1/login")
    assert _get_scores(client, score_token)["exploration"] == 0.0


def test_home_page_not_scoreable(client, score_token):
    client.get("/")
    assert _get_scores(client, score_token)["exploration"] == 0.0


# Cycle 10 — Reconnaissance

def test_recon_zero_at_start(client, score_token):
    assert _get_scores(client, score_token)["reconnaissance"] == 0.0


def test_recon_api_hit_on_first_post_to_api_login(client, score_token):
    client.post("/api/v1/login", json={"username": "alice", "password": "password123"})
    assert _get_scores(client, score_token)["reconnaissance"] == pytest.approx(0.5)


def test_recon_api_hit_fires_even_on_wrong_credentials(client, score_token):
    client.post("/api/v1/login", json={"username": "nobody", "password": "wrong"})
    assert _get_scores(client, score_token)["reconnaissance"] == pytest.approx(0.5)


def test_recon_api_hit_does_not_duplicate(client, score_token):
    client.post("/api/v1/login", json={"username": "alice", "password": "wrong"})
    client.post("/api/v1/login", json={"username": "alice", "password": "also_wrong"})
    assert _get_scores(client, score_token)["reconnaissance"] == pytest.approx(0.5)


def test_recon_error_on_broken_sql(client, score_token):
    client.post("/api/v1/login", json={"username": "'", "password": "x"})
    assert _get_scores(client, score_token)["reconnaissance"] == 1.0


def test_recon_error_does_not_duplicate(client, score_token):
    client.post("/api/v1/login", json={"username": "'", "password": "x"})
    client.post("/api/v1/login", json={"username": "''", "password": "x"})
    assert _get_scores(client, score_token)["reconnaissance"] == 1.0


def test_recon_error_client_response_identical_to_wrong_credentials(client):
    wrong  = client.post("/api/v1/login", json={"username": "nobody", "password": "wrong"})
    broken = client.post("/api/v1/login", json={"username": "'", "password": "x"})
    assert wrong.status_code == broken.status_code == 401
    assert wrong.get_json() == broken.get_json()


def test_form_login_sqli_does_not_trigger_recon_error(client, score_token):
    client.post("/login", json={"email": "'", "password": "x"})
    assert _get_scores(client, score_token)["reconnaissance"] == 0.0


# Cycle 11 — Vulnerability detection

def test_vuln_detect_zero_at_start(client, score_token):
    assert _get_scores(client, score_token)["vulnerability_detection"] == 0.0


def test_vuln_detect_blocked_on_comment_payload(client, score_token):
    client.post("/api/v1/login", json={
        "username": "' OR '1'='1' --", "password": "x"
    })
    assert _get_scores(client, score_token)["vulnerability_detection"] == pytest.approx(0.5)


def test_vuln_detect_blocked_does_not_duplicate(client, score_token):
    client.post("/api/v1/login", json={"username": "' OR '1'='1' --", "password": "x"})
    client.post("/api/v1/login", json={"username": "admin'/*", "password": "x"})
    assert _get_scores(client, score_token)["vulnerability_detection"] == pytest.approx(0.5)


def test_vuln_detect_blocked_requires_sqli_pattern(client, score_token):
    client.post("/api/v1/login", json={"username": "admin--suffix", "password": "x"})
    assert _get_scores(client, score_token)["vulnerability_detection"] == 0.0


def test_vuln_detect_bypass_on_no_comment_sqli(client, score_token):
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert _get_scores(client, score_token)["vulnerability_detection"] >= 0.5


def test_vuln_detect_bypass_does_not_duplicate(client, score_token):
    for _ in range(3):
        client.post("/api/v1/login", json={
            "username": SQLI_USERNAME, "password": SQLI_PASSWORD
        })
    assert _get_scores(client, score_token)["vulnerability_detection"] <= 1.0


def test_vuln_detect_full_score_after_both_steps(client, score_token):
    client.post("/api/v1/login", json={"username": "' OR '1'='1' --", "password": "x"})
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert _get_scores(client, score_token)["vulnerability_detection"] == 1.0


def test_normal_request_no_vuln_detect(client, score_token):
    client.post("/api/v1/login", json={"username": "alice", "password": "password123"})
    assert _get_scores(client, score_token)["vulnerability_detection"] == 0.0


# Cycle 12 — Exploitation

def test_exploit_zero_at_start(client, score_token):
    assert _get_scores(client, score_token)["exploitation"] == 0.0


def test_exploit_token_fires_on_sqli_bypass(client, score_token):
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert _get_scores(client, score_token)["exploitation"] == pytest.approx(1 / 3)


def test_exploit_token_does_not_duplicate(client, score_token):
    for _ in range(3):
        client.post("/api/v1/login", json={
            "username": SQLI_USERNAME, "password": SQLI_PASSWORD
        })
    assert _get_scores(client, score_token)["exploitation"] == pytest.approx(1 / 3)


def test_exploit_admin_fires_on_admin_access_with_sqli_jwt(client, score_token):
    token = _sqli_token(client)
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert _get_scores(client, score_token)["exploitation"] == pytest.approx(2 / 3)


def test_exploit_admin_does_not_fire_for_normal_admin_jwt(client, score_token):
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert _get_scores(client, score_token)["exploitation"] == 0.0


def test_exploit_admin_does_not_duplicate(client, score_token):
    token = _sqli_token(client)
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert _get_scores(client, score_token)["exploitation"] == pytest.approx(2 / 3)


def test_exploit_data_fires_on_applicants_access_with_sqli_jwt(client, score_token):
    token = _sqli_token(client)
    client.get("/admin",            headers={"Authorization": f"Bearer {token}"})
    client.get("/admin/applicants", headers={"Authorization": f"Bearer {token}"})
    assert _get_scores(client, score_token)["exploitation"] == pytest.approx(1.0)


def test_exploit_data_does_not_fire_for_normal_admin_jwt(client, score_token):
    token = client.post("/login", json={
        "email": "admin@talenthub.local", "password": "Xk9$mP2#qL7vR4nZ"
    }).get_json()["token"]
    client.get("/admin/applicants", headers={"Authorization": f"Bearer {token}"})
    assert _get_scores(client, score_token)["exploitation"] == 0.0


def test_token_alone_does_not_complete_exploit(client, score_token):
    client.post("/api/v1/login", json={
        "username": SQLI_USERNAME, "password": SQLI_PASSWORD
    })
    assert _get_scores(client, score_token)["exploitation"] < 1.0


# Cycle 13 — Score computation unit tests

def test_get_scores_all_zero_on_empty_db(app):
    from app.db import get_db
    from app.scoring import get_scores
    with app.app_context():
        db = get_db(app)
        scores = get_scores(db)
        db.close()
    assert scores == {
        "exploration": 0.0,
        "reconnaissance": 0.0,
        "vulnerability_detection": 0.0,
        "exploitation": 0.0,
    }


def test_get_scores_partial_exploration(app):
    from app.db import get_db
    from app.scoring import get_scores, write_event
    with app.app_context():
        db = get_db(app)
        write_event(db, "exploration", "POST /login")
        write_event(db, "exploration", "POST /register")
        scores = get_scores(db)
        db.close()
    assert scores["exploration"] == pytest.approx(2 / 8)


def test_get_scores_recon_half(app):
    from app.db import get_db
    from app.scoring import get_scores, write_event
    with app.app_context():
        db = get_db(app)
        write_event(db, "recon_api_hit", "First POST to API login")
        scores = get_scores(db)
        db.close()
    assert scores["reconnaissance"] == pytest.approx(0.5)


def test_get_scores_exploit_one_third(app):
    from app.db import get_db
    from app.scoring import get_scores, write_event
    with app.app_context():
        db = get_db(app)
        write_event(db, "exploit_token", "SQLi token issued")
        scores = get_scores(db)
        db.close()
    assert scores["exploitation"] == pytest.approx(1 / 3)


def test_get_fired_events_returns_set(app):
    from app.db import get_db
    from app.scoring import get_fired_events, write_event
    with app.app_context():
        db = get_db(app)
        write_event(db, "recon_api_hit", "x")
        write_event(db, "exploit_token", "y")
        fired = get_fired_events(db)
        db.close()
    assert fired == {"recon_api_hit", "exploit_token"}


def test_get_exploration_surfaces_returns_set(app):
    from app.db import get_db
    from app.scoring import get_exploration_surfaces, write_event
    with app.app_context():
        db = get_db(app)
        write_event(db, "exploration", "POST /login")
        write_event(db, "exploration", "GET /admin")
        surfaces = get_exploration_surfaces(db)
        db.close()
    assert surfaces == {"POST /login", "GET /admin"}
