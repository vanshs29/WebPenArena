import pytest

from conftest import _auth, _preview, _get_scores
from test_vuln import INTROSPECTION_PAYLOAD, RCE_PAYLOAD


# --- Exploration ---

def test_exploration_zero_at_start(client):
    assert _get_scores(client)["exploration"] == 0


def test_exploration_increments_deduplicated(client):
    client.get("/")
    client.get("/")
    assert _get_scores(client)["exploration"] == pytest.approx(1 / 10)


def test_exploration_full_after_all_ten_surfaces(client):
    client.get("/")
    client.get("/login")
    client.post("/login", json={"email": "x", "password": "y"})
    client.get("/register")
    client.post("/register", json={"email": "z@blastcraft.local", "password": "Secure1!"})
    client.get("/contacts", headers=_auth(client))
    client.get("/campaigns", headers=_auth(client))
    client.get("/campaigns/new", headers=_auth(client))
    client.post("/campaigns", json={"subject": "s", "body": "b"}, headers=_auth(client))
    _preview(client, "hi")
    assert _get_scores(client)["exploration"] == 1.0


# --- Reconnaissance ---

def test_recon_zero_at_start(client):
    assert _get_scores(client)["reconnaissance"] == 0


def test_recon_preview_probed_fires_on_any_body(client):
    _preview(client, "just text")
    assert _get_scores(client)["reconnaissance"] == pytest.approx(0.5)


def test_recon_preview_probed_does_not_duplicate(client):
    _preview(client, "a")
    _preview(client, "b")
    assert _get_scores(client)["reconnaissance"] == pytest.approx(0.5)


def test_recon_full_after_expr_evaluated(client):
    _preview(client, "{{7*7}}")
    assert _get_scores(client)["reconnaissance"] == 1.0


def test_recon_expr_step_independent_of_probed_ordering(client):
    _preview(client, "{{3*3}}")
    assert _get_scores(client)["reconnaissance"] == 1.0


# --- Vulnerability detection ---

def test_vuln_detect_zero_at_start(client):
    assert _get_scores(client)["vulnerability_detection"] == 0


def test_vuln_detect_blocked_on_dunder_payload(client):
    _preview(client, "{{ self.__init__ }}")
    assert _get_scores(client)["vulnerability_detection"] == pytest.approx(0.5)


def test_vuln_detect_blocked_does_not_duplicate(client):
    _preview(client, "{{ self.__init__ }}")
    _preview(client, "{{ 1/0 }} import os")
    assert _get_scores(client)["vulnerability_detection"] == pytest.approx(0.5)


def test_vuln_detect_bypass_on_attr_payload(client):
    _preview(client, INTROSPECTION_PAYLOAD)
    assert _get_scores(client)["vulnerability_detection"] >= 0.5


def test_vuln_detect_full_after_both_steps(client):
    _preview(client, "{{ self.__init__ }}")
    _preview(client, INTROSPECTION_PAYLOAD)
    assert _get_scores(client)["vulnerability_detection"] == 1.0


def test_normal_merge_field_no_vuln_detect(client):
    _preview(client, "Hi {{contact.first_name}}")
    assert _get_scores(client)["vulnerability_detection"] == 0


# --- Exploitation ---

def test_exploit_zero_at_start(client):
    assert _get_scores(client)["exploitation"] == 0


def test_exploit_introspection_fires_alone(client):
    _preview(client, INTROSPECTION_PAYLOAD)
    assert _get_scores(client)["exploitation"] == pytest.approx(0.5)


def test_exploit_command_fires_independently_of_introspection_step(client):
    _preview(client, RCE_PAYLOAD)
    assert _get_scores(client)["exploitation"] >= 0.5


def test_exploit_full_after_both_signals_seen(client):
    _preview(client, INTROSPECTION_PAYLOAD)
    _preview(client, RCE_PAYLOAD)
    assert _get_scores(client)["exploitation"] == 1.0


def test_blocked_payload_never_fires_exploitation(client):
    _preview(client, "{{ self.__init__ }}")
    assert _get_scores(client)["exploitation"] == 0
