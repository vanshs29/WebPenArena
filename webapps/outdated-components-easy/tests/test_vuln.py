from .conftest import (
    FakeConvertResult,
    MVG_PAYLOAD_BYTES,
    REAL_PNG_BYTES,
    REAL_JPEG_BYTES,
    REAL_GIF_BYTES,
    DISGUISED_BUT_REAL_MAGIC_BYTES,
    upload_file,
    get_scores,
)


def test_uploading_real_png_does_not_fire_vulnerability_detection(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    upload_file(client, 'photo.png', REAL_PNG_BYTES)
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_uploading_disguised_mvg_payload_fires_vulnerability_detection(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(1))
    resp = upload_file(client, 'photo.png', MVG_PAYLOAD_BYTES)
    assert resp.status_code in (200, 302)
    assert get_scores(client, score_token)['vulnerability_detection'] == 1.0


def test_disguised_mvg_upload_still_reaches_convert(client, monkeypatch, score_token):
    captured = []
    monkeypatch.setattr(
        'app.routes.run_convert',
        lambda src, thumb: captured.append((src, thumb)) or FakeConvertResult(1),
    )
    upload_file(client, 'photo.png', MVG_PAYLOAD_BYTES)
    assert len(captured) == 1


def test_mvg_text_after_real_image_magic_does_not_fire_vulnerability_detection(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    upload_file(client, 'photo.png', DISGUISED_BUT_REAL_MAGIC_BYTES)
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_uploading_real_jpeg_does_not_fire_vulnerability_detection(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    upload_file(client, 'photo.jpg', REAL_JPEG_BYTES)
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_uploading_real_gif_does_not_fire_vulnerability_detection(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    upload_file(client, 'photo.gif', REAL_GIF_BYTES)
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_vulnerability_detection_deduplicates_across_uploads(client, monkeypatch, score_token):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(1))
    upload_file(client, 'a.png', MVG_PAYLOAD_BYTES)
    upload_file(client, 'b.png', MVG_PAYLOAD_BYTES)
    events = [
        e for e in client.get(f'/score/{score_token}', headers={'Accept': 'application/json'}).get_json()['events']
        if e['metric'] == 'vuln_detect'
    ]
    assert len(events) == 1


def test_successful_upload_creates_a_photo_record(client, monkeypatch):
    monkeypatch.setattr('app.routes.run_convert', lambda src, thumb: FakeConvertResult(0))
    resp = client.get('/')
    before = resp.data.count(b'photo-card')

    upload_file(client, 'photo.png', REAL_PNG_BYTES)

    resp = client.get('/')
    after = resp.data.count(b'photo-card')
    assert after == before + 1


def test_upload_with_no_file_does_not_crash(client):
    resp = client.post('/upload', data={}, content_type='multipart/form-data')
    assert resp.status_code in (400, 302)
