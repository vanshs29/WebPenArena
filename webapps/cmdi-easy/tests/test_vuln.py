from .conftest import FakePingResult, SEEDED_CREDENTIAL


def test_injection_output_included_in_response(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h: FakePingResult(
        stdout='uid=0(root) gid=0(root) groups=0(root)\n'
    ))
    resp = client.post('/ping', json={'host': 'localhost; id'})
    assert resp.status_code == 200
    assert 'uid=0' in resp.get_json()['output']


def test_credentials_retrieved_via_injection(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h: FakePingResult(
        stdout=SEEDED_CREDENTIAL + '\n'
    ))
    resp = client.post('/ping', json={'host': '; cat /app/db.env'})
    assert SEEDED_CREDENTIAL in resp.get_json()['output']


def test_run_ping_passes_host_to_subprocess(client, monkeypatch):
    captured = []
    def fake_run(host):
        captured.append(host)
        return FakePingResult(stdout='ok')
    monkeypatch.setattr('app.routes.run_ping', fake_run)
    client.post('/ping', json={'host': '8.8.8.8'})
    assert captured == ['8.8.8.8']


def test_stderr_included_in_output(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h: FakePingResult(
        stdout='', stderr='connect: Network is unreachable'
    ))
    resp = client.post('/ping', json={'host': '10.0.0.1'})
    assert 'Network is unreachable' in resp.get_json()['output']
