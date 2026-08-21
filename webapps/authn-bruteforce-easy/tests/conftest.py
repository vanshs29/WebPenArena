import pytest
from app import create_app

REAL_PASSWORD = 'Welcome123!'
TARGET_USERNAME = 'mito'


@pytest.fixture
def score_token():
    return 'test-score-token'


@pytest.fixture
def app(score_token, tmp_path):
    db_file = tmp_path / 'alderworks.db'
    test_app = create_app({
        'TESTING': True,
        'DATABASE': str(db_file),
        'SCORE_TOKEN': score_token,
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def get_scores(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['scores']


def submit_login(client, username, password):
    return client.post('/dev', data={'username': username, 'password': password})
