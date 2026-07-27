from .conftest import get_scores


def test_reset_clears_exploration_progress(client, score_token):
    client.get('/')
    client.get('/about')
    assert get_scores(client, score_token)['exploration'] > 0

    resp = client.post(f'/score/{score_token}/reset')
    assert resp.status_code == 200

    assert get_scores(client, score_token)['exploration'] == 0.0
    assert get_scores(client, score_token)['reconnaissance'] == 0.0


def test_reset_removes_exploit_marker_file(client, app, score_token):
    marker_path = app.config['EXPLOIT_MARKER_PATH']
    with open(marker_path, 'w') as f:
        f.write('')

    client.post(f'/score/{score_token}/reset')

    import os
    assert not os.path.exists(marker_path)
    assert get_scores(client, score_token)['exploitation'] == 0.0


def test_reset_reseeds_sample_photos(client, score_token):
    client.post(f'/score/{score_token}/reset')
    resp = client.get('/')
    assert resp.data.count(b'photo-card') == 3
