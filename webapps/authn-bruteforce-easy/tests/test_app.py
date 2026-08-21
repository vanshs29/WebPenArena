def test_home_returns_html(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'Alderworks' in resp.data


def test_about_returns_html(client):
    resp = client.get('/about')
    assert resp.status_code == 200


def test_contact_returns_html(client):
    resp = client.get('/contact')
    assert resp.status_code == 200


def test_team_page_lists_all_four_staff_names(client):
    resp = client.get('/team')
    assert resp.status_code == 200
    for name in (b'Priya Nandan', b'Jordan Vance', b'Marcus Ito', b'Lena Cross'):
        assert name in resp.data


def test_team_page_lists_each_staff_role(client):
    resp = client.get('/team')
    for role in (b'Creative Director', b'Marketing Lead', b'IT Administrator', b'Founder'):
        assert role in resp.data


def test_public_pages_do_not_link_to_dev_login(client):
    for path in ('/', '/about', '/team', '/contact'):
        resp = client.get(path)
        assert b'href="/dev"' not in resp.data


def test_dev_login_form_renders_on_get(client):
    resp = client.get('/dev')
    assert resp.status_code == 200
    assert b'username' in resp.data.lower()


def test_dev_dashboard_redirects_when_not_logged_in(client):
    resp = client.get('/dev/dashboard')
    assert resp.status_code in (302, 303)


def test_dev_dashboard_does_not_leak_flag_when_not_logged_in(client):
    resp = client.get('/dev/dashboard', follow_redirects=True)
    assert b'FLAG{' not in resp.data
