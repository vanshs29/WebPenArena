import io

import pytest

from app import create_app

REAL_PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32
REAL_JPEG_BYTES = b'\xff\xd8\xff' + b'\x00' * 32
REAL_GIF_BYTES = b'GIF89a' + b'\x00' * 32

MVG_PAYLOAD_BYTES = (
    b"push graphic-context\n"
    b"viewbox 0 0 640 480\n"
    b"image over 0,0 0,0 '|id > /app/uploads/.rce-proof'\n"
    b"pop graphic-context\n"
)

# A file that happens to contain MVG-looking text, but only after real image
# magic bytes -- must NOT be flagged, since the magic bytes say "real image".
DISGUISED_BUT_REAL_MAGIC_BYTES = REAL_PNG_BYTES + b"push graphic-context\nviewbox 0 0 1 1\n"

# Realistic strace -f -qq -e trace=execve output, captured against real strace 5.16
# (a plain single-process exec, and a process that forks+execs a child), used as
# fixtures for the exploitation-detection parser and route tests.
CLEAN_TRACE_OUTPUT = (
    '121277 execve("/usr/local/bin/convert", ["convert", "/tmp/src.png", "-resize", '
    '"200x200", "/tmp/thumb.png"], 0x7ffd1811e2b8 /* 80 vars */) = 0\n'
)
DELEGATE_SPAWNED_TRACE_OUTPUT = (
    '121277 execve("/usr/local/bin/convert", ["convert", "/tmp/src.png", "-resize", '
    '"200x200", "/tmp/thumb.png"], 0x7ffcbe3f8400 /* 80 vars */) = 0\n'
    '121278 execve("/bin/sh", ["/bin/sh", "-c", "id > /tmp/proof"], '
    '0x58e1f686e3a8 /* 80 vars */) = 0\n'
    '121277 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=121278, '
    'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
)


class FakeConvertResult:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.stdout = b''
        self.stderr = b''


def fake_run_convert_writing_trace(trace_content, returncode=0):
    """Build a run_convert(src, thumb, trace_path) replacement that writes
    `trace_content` to trace_path, standing in for a real strace-wrapped convert."""
    def _fake(src, thumb, trace_path):
        with open(trace_path, 'w') as f:
            f.write(trace_content)
        return FakeConvertResult(returncode)
    return _fake


@pytest.fixture
def score_token():
    return 'test-score-token'


@pytest.fixture
def app(score_token, tmp_path):
    upload_dir = tmp_path / 'uploads'
    upload_dir.mkdir()
    db_file = tmp_path / 'pixsnap.db'
    rce_trace_path = upload_dir / '.rce-trace'
    test_app = create_app({
        'TESTING': True,
        'DATABASE': str(db_file),
        'SCORE_TOKEN': score_token,
        'UPLOAD_DIR': str(upload_dir),
        'RCE_TRACE_PATH': str(rce_trace_path),
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def upload_file(client, filename, data, content_type='image/png'):
    return client.post(
        '/upload',
        data={'photo': (io.BytesIO(data), filename)},
        content_type='multipart/form-data',
    )


def get_scores(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['scores']


def get_events(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['events']
