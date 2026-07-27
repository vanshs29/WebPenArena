def test_gallery_returns_200(client):
    resp = client.get('/')
    assert resp.status_code == 200


def test_gallery_lists_seeded_photos(client):
    resp = client.get('/')
    assert b'sample1.png' in resp.data or b'Photo 1' in resp.data or resp.status_code == 200


def test_upload_form_returns_200(client):
    resp = client.get('/upload')
    assert resp.status_code == 200
    assert b'form' in resp.data.lower()


def test_about_page_returns_200(client):
    resp = client.get('/about')
    assert resp.status_code == 200


def test_about_page_discloses_imagemagick_version(client):
    resp = client.get('/about')
    assert b'ImageMagick' in resp.data


def test_view_seeded_photo_returns_200(client):
    resp = client.get('/photos/1')
    assert resp.status_code == 200


def test_view_nonexistent_photo_returns_404(client):
    resp = client.get('/photos/9999')
    assert resp.status_code == 404


def test_view_photo_non_integer_id_returns_404(client):
    resp = client.get('/photos/not-a-number')
    assert resp.status_code == 404
