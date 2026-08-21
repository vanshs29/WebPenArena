from .conftest import REAL_PASSWORD, TARGET_USERNAME, submit_login


def test_login_with_correct_credentials_redirects_to_dashboard(client):
    resp = submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    assert resp.status_code in (302, 303)
    assert '/dev/dashboard' in resp.headers['Location']


def test_login_with_correct_credentials_grants_dashboard_access(client):
    submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    resp = client.get('/dev/dashboard')
    assert resp.status_code == 200
    assert b'FLAG{authn_alderworks_easy}' in resp.data


def test_login_with_wrong_password_returns_generic_error(client):
    resp = submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert resp.status_code == 401
    assert b'Invalid username or password.' in resp.data


def test_login_with_nonexistent_username_returns_same_generic_error(client):
    resp = submit_login(client, 'pnandan', 'anything')
    assert resp.status_code == 401
    assert b'Invalid username or password.' in resp.data


def test_bad_username_and_bad_password_return_identical_error_bodies(client):
    resp_bad_user = submit_login(client, 'nobody', 'whatever')
    resp_bad_pass = submit_login(client, TARGET_USERNAME, 'whatever')
    assert resp_bad_user.data == resp_bad_pass.data


def test_repeated_failed_attempts_are_never_blocked(client):
    for _ in range(20):
        resp = submit_login(client, TARGET_USERNAME, 'wrong-password')
        assert resp.status_code == 401

    resp = submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    assert resp.status_code in (302, 303)


def test_dev_login_uses_parameterized_lookup_not_vulnerable_to_sqli(client):
    resp = submit_login(client, "' OR '1'='1", "' OR '1'='1")
    assert resp.status_code == 401
