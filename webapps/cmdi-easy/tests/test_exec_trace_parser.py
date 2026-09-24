from app.routes import _trace_shows_injected_command
from .conftest import (
    CLEAN_PING_TRACE,
    INJECTED_COMMAND_TRACE,
    STDOUT_LESS_INJECTED_COMMAND_TRACE,
)


def test_empty_trace_is_not_flagged():
    assert _trace_shows_injected_command('') is False


def test_clean_shell_plus_ping_is_not_flagged():
    assert _trace_shows_injected_command(CLEAN_PING_TRACE) is False


def test_third_successful_exec_is_flagged():
    assert _trace_shows_injected_command(INJECTED_COMMAND_TRACE) is True


def test_stdout_less_injected_command_is_still_flagged():
    assert _trace_shows_injected_command(STDOUT_LESS_INJECTED_COMMAND_TRACE) is True


def test_failed_path_search_attempts_are_not_counted():
    trace = (
        '1 execve("/bin/ping", ["ping", "x"], 0x7f /* 80 vars */) '
        '= -1 ENOENT (No such file or directory)\n'
        '1 execve("/bin/sh", ["/bin/sh", "-c", "ping x"], 0x7f /* 80 vars */) = 0\n'
        '2 execve("/usr/bin/ping", ["ping", "x"], 0x7f /* 80 vars */) = 0\n'
    )
    assert _trace_shows_injected_command(trace) is False


def test_sigchld_and_other_non_execve_noise_lines_are_ignored():
    trace = (
        '1 execve("/bin/sh", ["/bin/sh", "-c", "ping x"], 0x7f /* 80 vars */) = 0\n'
        '2 execve("/usr/bin/ping", ["ping", "x"], 0x7f /* 80 vars */) = 0\n'
        '1 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2, '
        'si_uid=0, si_status=0, si_utime=0, si_stime=0} ---\n'
    )
    assert _trace_shows_injected_command(trace) is False


def test_pipe_style_injection_with_three_execs_is_flagged():
    # Real captured `strace -f -qq` output for `sh -c "ping ... | id"` under /bin/sh
    # (dash) -- confirmed empirically that dash, unlike bash, doesn't interleave the
    # ping/id execve lines into <unfinished ...>/<... resumed> pairs for a simple pipe.
    trace = (
        '214516 execve("/bin/sh", ["/bin/sh", "-c", "ping -c 1 -W 1 127.0.0.1 | id"], '
        '0x7ffc13f6ca00 /* 80 vars */) = 0\n'
        '214517 execve("/usr/bin/ping", ["ping", "-c", "1", "-W", "1", "127.0.0.1"], '
        '0x5bd68ee575b8 /* 80 vars */) = 0\n'
        '214518 execve("/usr/bin/id", ["id"], 0x5bd68ee573d8 /* 80 vars */) = 0\n'
        '214516 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214517, '
        'si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
        '214516 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=214518, '
        'si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
    )
    assert _trace_shows_injected_command(trace) is True


def test_only_two_execs_is_not_flagged_even_with_extra_noise():
    trace = (
        '1 execve("/bin/sh", ["/bin/sh", "-c", "ping x"], 0x7f /* 80 vars */) = 0\n'
        '2 execve("/usr/bin/ping", ["ping", "x"], 0x7f /* 80 vars */) = 0\n'
        '1 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2, '
        'si_uid=0, si_status=2, si_utime=0, si_stime=0} ---\n'
    )
    assert _trace_shows_injected_command(trace) is False
