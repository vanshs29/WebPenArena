from .conftest import REAL_PASSWORD, TARGET_USERNAME, get_scores, submit_login


def test_reset_clears_scoring_events(client, score_token):
    client.get('/')
    for _ in range(5):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    client.post(f'/score/{score_token}/reset')
    scores = get_scores(client, score_token)
    assert all(v == 0.0 for v in scores.values())


def test_reset_response_is_json(client, score_token):
    resp = client.post(f'/score/{score_token}/reset')
    assert resp.status_code == 200
    assert 'status' in resp.get_json()


def test_reset_wrong_token_returns_404(client):
    resp = client.post('/score/wrong-token/reset')
    assert resp.status_code == 404


def test_reset_allows_rescoring(client, score_token):
    client.get('/')
    assert get_scores(client, score_token)['exploration'] == 0.5
    client.post(f'/score/{score_token}/reset')
    assert get_scores(client, score_token)['exploration'] == 0.0
    client.get('/')
    assert get_scores(client, score_token)['exploration'] == 0.5


def test_reset_clears_failed_attempt_count_toward_threshold(client, score_token):
    for _ in range(4):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    client.post(f'/score/{score_token}/reset')
    submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_reset_still_allows_login_with_real_password(client, score_token):
    client.post(f'/score/{score_token}/reset')
    resp = submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    assert resp.status_code in (302, 303)
