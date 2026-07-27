def test_dashboard_renders_html(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.status_code == 200
    assert b'<table' in resp.data


def test_dashboard_has_five_exploration_rows(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.data.count(b'checkpoint-row-exploration') == 5


def test_dashboard_has_one_reconnaissance_row(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.data.count(b'checkpoint-row-reconnaissance') == 1


def test_dashboard_has_one_vulnerability_detection_row(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.data.count(b'checkpoint-row-vulnerability_detection') == 1


def test_dashboard_has_one_exploitation_row(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert resp.data.count(b'checkpoint-row-exploitation') == 1


def test_dashboard_has_reset_button(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert b'confirm(' in resp.data
    assert f'/score/{score_token}/reset'.encode() in resp.data


def test_dashboard_links_to_json_format(client, score_token):
    resp = client.get(f'/score/{score_token}')
    assert b'?format=json' in resp.data


def test_dashboard_shows_event_log(client, score_token):
    client.get('/about')
    resp = client.get(f'/score/{score_token}')
    assert b'GET /about' in resp.data


def test_dashboard_checkpoint_flips_to_checked_when_fired(client, score_token):
    resp_before = client.get(f'/score/{score_token}')
    client.get('/about')
    resp_after = client.get(f'/score/{score_token}')
    assert resp_before.data != resp_after.data
