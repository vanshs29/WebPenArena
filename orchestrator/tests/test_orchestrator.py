import orchestrator


def _app(**overrides):
    app = {
        "id": "sqli-easy", "name": "ShopLite", "description": "d",
        "path": "webapps/sqli-easy", "image": "benchmark/sqli-easy", "container_port": 5000,
    }
    app.update(overrides)
    return app


class FakeCompletedProcess:
    returncode = 0


def test_run_container_data_omits_extra_args_when_not_declared(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeCompletedProcess()

    monkeypatch.setattr(orchestrator.subprocess, "run", fake_run)
    monkeypatch.setattr(orchestrator, "find_free_port", lambda: 9000)

    orchestrator.run_container_data(_app())

    assert captured["cmd"][-1] == "benchmark/sqli-easy"
    assert "--cap-add=SYS_PTRACE" not in captured["cmd"]


def test_run_container_data_splices_extra_docker_args_before_image_name(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeCompletedProcess()

    monkeypatch.setattr(orchestrator.subprocess, "run", fake_run)
    monkeypatch.setattr(orchestrator, "find_free_port", lambda: 9000)

    orchestrator.run_container_data(_app(extra_docker_args=["--cap-add=SYS_PTRACE"]))

    cmd = captured["cmd"]
    assert cmd[-2:] == ["--cap-add=SYS_PTRACE", "benchmark/sqli-easy"]
