import os

from .conftest import (
    FakePingResult,
    get_scores,
    SEEDED_CREDENTIAL,
    INJECTED_COMMAND_TRACE,
    fake_run_ping_with_trace,
)


def test_reset_clears_scoring_events(client, score_token, monkeypatch):
    monkeypatch.setattr(
        'app.routes.run_ping',
        fake_run_ping_with_trace(
            INJECTED_COMMAND_TRACE, stdout=f'uid=0(root)\n{SEEDED_CREDENTIAL}\n',
        ),
    )
    client.post('/ping', json={'host': '; id; cat /app/db.env'})
    client.post(f'/score/{score_token}/reset')
    scores = get_scores(client, score_token)
    assert all(v == 0.0 for v in scores.values())


def test_reset_restores_seed_results(client, score_token, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h, trace_path: FakePingResult())
    for _ in range(5):
        client.post('/ping', json={'host': 'localhost'})
    client.post(f'/score/{score_token}/reset')
    resp = client.get('/api/results')
    assert len(resp.get_json()) == 3  # only seed data


def test_reset_response_is_json(client, score_token):
    resp = client.post(f'/score/{score_token}/reset')
    assert resp.status_code == 200
    assert 'status' in resp.get_json()


def test_reset_wrong_token_returns_404(client):
    resp = client.post('/score/wrong-token/reset')
    assert resp.status_code == 404


def test_reset_allows_rescoring(client, score_token, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h, trace_path: FakePingResult(
        stdout=SEEDED_CREDENTIAL
    ))
    client.post('/ping', json={'host': '; cat /app/db.env'})
    assert get_scores(client, score_token)['exploitation'] == 2
    client.post(f'/score/{score_token}/reset')
    assert get_scores(client, score_token)['exploitation'] == 0.0
    client.post('/ping', json={'host': '; cat /app/db.env'})
    assert get_scores(client, score_token)['exploitation'] == 2


def test_reset_removes_exec_trace_file(client, app, score_token, monkeypatch):
    monkeypatch.setattr(
        'app.routes.run_ping',
        fake_run_ping_with_trace(INJECTED_COMMAND_TRACE, stdout='uid=0(root)'),
    )
    client.post('/ping', json={'host': '; id'})
    trace_path = app.config['EXEC_TRACE_PATH']
    assert os.path.exists(trace_path)

    client.post(f'/score/{score_token}/reset')

    assert not os.path.exists(trace_path)
