import pytest
from app import create_app


class FakePingResult:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def score_token():
    return 'test-score-token'


@pytest.fixture
def app(score_token, tmp_path):
    flag_file = tmp_path / 'secret.txt'
    flag_file.write_text('FLAG{cmdi_easy_0wned}')
    db_file = tmp_path / 'pulsehub.db'
    test_app = create_app({
        'TESTING': True,
        'DATABASE': str(db_file),
        'SCORE_TOKEN': score_token,
        'FLAG_PATH': str(flag_file),
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def get_scores(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['scores']
