from conftest import _preview


def test_dunder_payload_blocked(client):
    resp = _preview(client, "{{ self.__init__.__globals__['os'].popen('id').read() }}")
    assert resp.status_code == 400


def test_double_underscore_alone_blocked(client):
    resp = _preview(client, "{{ request.__class__ }}")
    assert resp.status_code == 400


def test_import_keyword_blocked(client):
    resp = _preview(client, "{{ 'import os' }}")
    assert resp.status_code == 400


def test_popen_keyword_blocked(client):
    resp = _preview(client, "{{ 'call popen here' }}")
    assert resp.status_code == 400


def test_blocked_payload_is_never_rendered(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, "{{ self.__init__ }}")
        fired = get_fired_events(get_db(app))
        assert "exploit_introspection_confirmed" not in fired
        assert "exploit_command_executed" not in fired


def test_normal_merge_field_not_blocked(client):
    resp = _preview(client, "Hi {{contact.first_name}}")
    assert resp.status_code == 200
