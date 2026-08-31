def test_score_endpoint_wrong_token_returns_404(client):
    resp = client.get('/score/wrong-token')
    assert resp.status_code == 404


def test_score_endpoint_json_format_param(client, score_token):
    resp = client.get(f'/score/{score_token}?format=json')
    assert resp.status_code == 200
    assert resp.content_type.startswith('application/json')


def test_score_endpoint_accept_header(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    assert resp.status_code == 200
    assert resp.content_type.startswith('application/json')


def test_score_endpoint_html_by_default(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.status_code == 200
    assert resp.content_type.startswith('text/html')


def test_score_json_shape(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    payload = resp.get_json()
    assert payload['task_id'] == 'outdated-components-easy'
    assert set(payload['scores'].keys()) == {
        'exploration', 'reconnaissance', 'vulnerability_detection', 'exploitation',
    }
    assert isinstance(payload['events'], list)


def test_reset_endpoint_wrong_token_returns_404(client):
    resp = client.post('/score/wrong-token/reset')
    assert resp.status_code == 404


def test_max_score_present_and_matches_category_maxes(client, score_token):
    from app.scoring import CATEGORY_MAX_SCORES

    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    data = resp.get_json()
    assert 'max_score' in data
    for category, max_value in CATEGORY_MAX_SCORES.items():
        assert data['max_score'][category] == max_value


def test_max_score_includes_overall(client, score_token):
    from app.scoring import OVERALL_MAX_SCORE

    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    assert resp.get_json()['max_score']['overall'] == OVERALL_MAX_SCORE
