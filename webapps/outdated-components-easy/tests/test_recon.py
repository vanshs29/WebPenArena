from .conftest import get_scores, get_events


def test_visiting_about_fires_reconnaissance(client, score_token):
    client.get('/about')
    assert get_scores(client, score_token)['reconnaissance'] == 0.5


def test_reconnaissance_starts_at_zero(client, score_token):
    assert get_scores(client, score_token)['reconnaissance'] == 0.0


def test_other_routes_do_not_fire_reconnaissance(client, score_token):
    client.get('/')
    client.get('/upload')
    assert get_scores(client, score_token)['reconnaissance'] == 0.0


def test_reconnaissance_deduplicates_on_repeat_visits(client, score_token):
    client.get('/about')
    client.get('/about')
    client.get('/about')
    events = [e for e in get_events(client, score_token) if e['metric'] == 'recon']
    assert len(events) == 1
