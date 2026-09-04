from conftest import _preview


def test_preview_renders_first_name(client):
    resp = _preview(client, "Hi {{contact.first_name}}!")
    assert resp.status_code == 200
    assert resp.get_json()["rendered"] == "Hi Jordan!"


def test_preview_renders_multiple_fields(client):
    resp = _preview(client, "{{contact.first_name}} {{contact.last_name}} — {{contact.company}}")
    assert resp.get_json()["rendered"] == "Jordan Lee — Example Co"


def test_preview_requires_nonempty_template(client):
    resp = _preview(client, "")
    assert resp.status_code == 400


def test_preview_plain_text_passes_through(client):
    resp = _preview(client, "No merge fields here.")
    assert resp.get_json()["rendered"] == "No merge fields here."
