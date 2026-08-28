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


SEEDED_CREDENTIAL = 'DB_PASSWORD=Xk9mQ2vLp8wRt5Nz'


@pytest.fixture
def app(score_token, tmp_path):
    secret_file = tmp_path / 'db.env'
    secret_file.write_text(
        'DB_HOST=127.0.0.1\n'
        'DB_USER=pulsehub_admin\n'
        f'{SEEDED_CREDENTIAL}\n'
        'DB_NAME=pulsehub_prod\n'
    )
    db_file = tmp_path / 'pulsehub.db'
    test_app = create_app({
        'TESTING': True,
        'DATABASE': str(db_file),
        'SCORE_TOKEN': score_token,
        'SECRET_FILE_PATH': str(secret_file),
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def get_scores(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['scores']
