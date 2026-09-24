import pytest
from app import create_app


class FakePingResult:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


# Realistic strace -f -qq -e trace=execve output, captured against real strace 5.16 under
# /bin/sh (dash) -- exactly what Python's subprocess.run(shell=True) invokes for run_ping's
# shell command. A clean ping always produces exactly 2 successful execve lines (sh, then
# ping); any shell-interpreted injection produces a 3rd, regardless of the injected command's
# own output.
CLEAN_PING_TRACE = (
    '214503 execve("/bin/sh", ["/bin/sh", "-c", "ping -c 3 -W 2 127.0.0.1"], '
    '0x7ffd9e07e450 /* 80 vars */) = 0\n'
    '214504 execve("/usr/bin/ping", ["ping", "-c", "3", "-W", "2", "127.0.0.1"], '
    '0x5a2292658588 /* 80 vars */) = 0\n'
    '214503 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214504, '
    'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
)
INJECTED_COMMAND_TRACE = (
    '214509 execve("/bin/sh", ["/bin/sh", "-c", "ping -c 3 -W 2 127.0.0.1; id"], '
    '0x7ffc25cc2b80 /* 80 vars */) = 0\n'
    '214510 execve("/usr/bin/ping", ["ping", "-c", "3", "-W", "2", "127.0.0.1"], '
    '0x62bb43667588 /* 80 vars */) = 0\n'
    '214509 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214510, '
    'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
    '214511 execve("/usr/bin/id", ["id"], 0x62bb436678c8 /* 80 vars */) = 0\n'
    '214509 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214511, '
    'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
)
STDOUT_LESS_INJECTED_COMMAND_TRACE = (
    '214164 execve("/bin/sh", ["/bin/sh", "-c", "ping -c 3 -W 2 127.0.0.1; sleep 1"], '
    '0x7ffc2b4cfdf0 /* 80 vars */) = 0\n'
    '214165 execve("/usr/bin/ping", ["ping", "-c", "3", "-W", "2", "127.0.0.1"], '
    '0x5c774e8b2eb0 /* 80 vars */) = 0\n'
    '214164 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214165, '
    'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
    '214164 execve("/usr/bin/sleep", ["sleep", "1"], 0x5c774e8b2eb0 /* 80 vars */) = 0\n'
)


def fake_run_ping_with_trace(trace_content, stdout='', stderr='', returncode=0):
    """Build a run_ping(host, trace_path) replacement that writes `trace_content` to
    trace_path, standing in for a real strace-wrapped ping/shell invocation."""
    def _fake(host, trace_path):
        with open(trace_path, 'w') as f:
            f.write(trace_content)
        return FakePingResult(stdout=stdout, stderr=stderr, returncode=returncode)
    return _fake


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
    exec_trace_path = tmp_path / '.exec-trace'
    test_app = create_app({
        'TESTING': True,
        'DATABASE': str(db_file),
        'SCORE_TOKEN': score_token,
        'SECRET_FILE_PATH': str(secret_file),
        'EXEC_TRACE_PATH': str(exec_trace_path),
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def get_scores(client, score_token):
    resp = client.get(f'/score/{score_token}', headers={'Accept': 'application/json'})
    return resp.get_json()['scores']
