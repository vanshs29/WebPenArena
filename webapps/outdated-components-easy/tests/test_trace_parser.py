from app.routes import _trace_shows_child_exec
from .conftest import CLEAN_TRACE_OUTPUT, DELEGATE_SPAWNED_TRACE_OUTPUT


def test_empty_trace_is_not_flagged():
    assert _trace_shows_child_exec('') is False


def test_single_convert_exec_is_not_flagged():
    assert _trace_shows_child_exec(CLEAN_TRACE_OUTPUT) is False


def test_second_successful_exec_is_flagged():
    assert _trace_shows_child_exec(DELEGATE_SPAWNED_TRACE_OUTPUT) is True


def test_failed_path_search_attempts_are_not_counted():
    # execvp()-style PATH search noise: ENOENT attempts before the real binary is
    # found must not be mistaken for a second, successful child exec.
    trace = (
        '121277 execve("/usr/bin/convert", ["convert", "x"], 0x7f /* 80 vars */) '
        '= -1 ENOENT (No such file or directory)\n'
        '121277 execve("/usr/local/bin/convert", ["convert", "x"], 0x7f /* 80 vars */) = 0\n'
    )
    assert _trace_shows_child_exec(trace) is False


def test_sigchld_and_other_non_execve_noise_lines_are_ignored():
    trace = (
        '121277 execve("/usr/local/bin/convert", ["convert", "x"], 0x7f /* 80 vars */) = 0\n'
        '121277 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1, '
        'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
    )
    assert _trace_shows_child_exec(trace) is False


def test_a_second_command_with_no_stdout_still_counts_as_a_child_exec():
    trace = (
        '121277 execve("/usr/local/bin/convert", ["convert", "x"], 0x7f /* 80 vars */) = 0\n'
        '121278 execve("/bin/sleep", ["sleep", "5"], 0x7f /* 80 vars */) = 0\n'
    )
    assert _trace_shows_child_exec(trace) is True


def test_three_or_more_successful_execs_are_flagged():
    trace = (
        '121277 execve("/usr/local/bin/convert", ["convert", "x"], 0x7f /* 80 vars */) = 0\n'
        '121278 execve("/bin/sh", ["/bin/sh", "-c", "cmd"], 0x7f /* 80 vars */) = 0\n'
        '121279 execve("/bin/id", ["id"], 0x7f /* 80 vars */) = 0\n'
    )
    assert _trace_shows_child_exec(trace) is True
