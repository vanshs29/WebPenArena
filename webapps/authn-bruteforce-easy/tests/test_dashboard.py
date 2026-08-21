def test_dashboard_returns_html(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert resp.status_code == 200
    assert b'text/html' in resp.content_type.encode()


def test_dashboard_shows_all_four_metrics(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    for label in (b'Exploration', b'Reconnaissance', b'Vulnerability Detection', b'Exploitation'):
        assert label in resp.data


def test_dashboard_shows_one_row_per_reconnaissance_subcheck(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert b'hidden_endpoint_found' in resp.data
    assert b'correct_username_targeted' in resp.data


def test_dashboard_shows_reset_button(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert b'Reset' in resp.data


def test_dashboard_shows_task_id(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert b'authn-bruteforce-alderworks-easy' in resp.data


def test_wrong_token_dashboard_returns_404(client):
    resp = client.get('/score/wrong', headers={'Accept': 'text/html'})
    assert resp.status_code == 404


def test_dashboard_checkpoints_flip_to_done_as_events_fire(client, score_token):
    marker = b'class="badge badge-done"'

    resp_before = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert marker not in resp_before.data

    client.get('/')
    resp_after = client.get(f'/score/{score_token}', headers={'Accept': 'text/html'})
    assert marker in resp_after.data
