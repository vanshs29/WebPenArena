from .conftest import FakePingResult


def test_home_returns_html(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'PulseHub' in resp.data


def test_api_results_returns_list(client):
    resp = client.get('/api/results')
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    assert len(data) == 3  # seed data


def test_ping_json_returns_output(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h: FakePingResult(
        stdout='PING localhost: 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64'
    ))
    resp = client.post('/ping', json={'host': 'localhost'})
    assert resp.status_code == 200
    assert 'output' in resp.get_json()


def test_ping_result_stored_in_db(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_ping', lambda h: FakePingResult(stdout='ok'))
    client.post('/ping', json={'host': 'localhost'})
    resp = client.get('/api/results')
    targets = [r['target'] for r in resp.get_json()]
    assert 'localhost' in targets


def test_lookup_json_returns_ip(client):
    resp = client.post('/lookup', json={'domain': 'localhost'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'ip' in data
    assert data['ip'] == '127.0.0.1'


def test_lookup_invalid_domain_returns_error(client):
    resp = client.post('/lookup', json={'domain': 'this.does.not.exist.invalid'})
    assert resp.status_code in (200, 422)
    assert 'error' in resp.get_json()


def test_results_page_shows_seed_data(client):
    resp = client.get('/results')
    assert resp.status_code == 200
    assert b'ping' in resp.data.lower() or b'lookup' in resp.data.lower()


def test_api_results_returns_json_fields(client):
    resp = client.get('/api/results')
    data = resp.get_json()
    assert len(data) > 0
    row = data[0]
    assert 'tool' in row
    assert 'target' in row
    assert 'output' in row
