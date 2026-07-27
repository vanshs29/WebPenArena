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
