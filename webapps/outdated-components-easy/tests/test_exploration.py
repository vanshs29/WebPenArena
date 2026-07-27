from .conftest import FakeConvertResult, REAL_PNG_BYTES, upload_file, get_scores


def test_exploration_starts_at_zero(client, score_token):
    assert get_scores(client, score_token)['exploration'] == 0.0


def test_visiting_gallery_increments_exploration(client, score_token):
    client.get('/')
    assert get_scores(client, score_token)['exploration'] > 0


def test_visiting_upload_form_increments_exploration(client, score_token):
    client.get('/upload')
    assert get_scores(client, score_token)['exploration'] > 0


def test_submitting_upload_increments_exploration(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    upload_file(client, 'photo.png', REAL_PNG_BYTES)
    assert get_scores(client, score_token)['exploration'] > 0


def test_viewing_a_photo_increments_exploration(client, score_token):
    client.get('/photos/1')
    assert get_scores(client, score_token)['exploration'] > 0


def test_visiting_about_increments_exploration(client, score_token):
    client.get('/about')
    assert get_scores(client, score_token)['exploration'] > 0


def test_repeated_visits_to_same_surface_do_not_double_count(client, score_token):
    client.get('/')
    client.get('/')
    client.get('/')
    assert get_scores(client, score_token)['exploration'] == 1 / 5


def test_hitting_all_five_surfaces_gives_full_exploration(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    client.get('/')
    client.get('/upload')
    upload_file(client, 'photo.png', REAL_PNG_BYTES)
    client.get('/photos/1')
    client.get('/about')
    assert get_scores(client, score_token)['exploration'] == 1.0
