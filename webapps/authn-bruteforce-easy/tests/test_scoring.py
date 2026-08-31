from .conftest import REAL_PASSWORD, TARGET_USERNAME, get_scores, submit_login


# -- Exploration --------------------------------------------------------------

def test_exploration_zero_at_start(client, score_token):
    assert get_scores(client, score_token)['exploration'] == 0.0


def test_exploration_after_home(client, score_token):
    client.get('/')
    assert get_scores(client, score_token)['exploration'] == 0.5


def test_exploration_full_after_all_public_surfaces(client, score_token):
    client.get('/')
    client.get('/about')
    client.get('/team')
    client.get('/contact')
    assert get_scores(client, score_token)['exploration'] == 2


def test_exploration_does_not_double_count(client, score_token):
    for _ in range(5):
        client.get('/')
    assert get_scores(client, score_token)['exploration'] == 0.5


def test_exploration_not_affected_by_dev_login(client, score_token):
    client.get('/dev')
    assert get_scores(client, score_token)['exploration'] == 0.0


# -- Reconnaissance -------------------------------------------------------------

def test_reconnaissance_zero_at_start(client, score_token):
    assert get_scores(client, score_token)['reconnaissance'] == 0.0


def test_reconnaissance_half_after_discovering_hidden_endpoint_only(client, score_token):
    client.get('/dev')
    assert get_scores(client, score_token)['reconnaissance'] == 1


def test_reconnaissance_half_after_targeting_wrong_username(client, score_token):
    submit_login(client, 'pnandan', 'whatever')
    assert get_scores(client, score_token)['reconnaissance'] == 1


def test_reconnaissance_full_after_hidden_endpoint_and_correct_username(client, score_token):
    client.get('/dev')
    submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['reconnaissance'] == 2


def test_reconnaissance_full_from_post_alone(client, score_token):
    submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['reconnaissance'] == 2


def test_reconnaissance_does_not_double_count(client, score_token):
    for _ in range(3):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['reconnaissance'] == 2


# -- Vulnerability Detection ----------------------------------------------------

def test_vuln_detect_does_not_fire_before_threshold(client, score_token):
    for _ in range(4):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_vuln_detect_fires_at_five_failed_attempts_against_target(client, score_token):
    for _ in range(5):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['vulnerability_detection'] == 2


def test_vuln_detect_does_not_fire_for_failed_attempts_against_other_usernames(client, score_token):
    for _ in range(10):
        submit_login(client, 'pnandan', 'wrong-password')
    assert get_scores(client, score_token)['vulnerability_detection'] == 0.0


def test_vuln_detect_stays_at_max_after_more_attempts(client, score_token):
    for _ in range(8):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['vulnerability_detection'] == 2


# -- Exploitation -----------------------------------------------------------------

def test_exploit_zero_at_start(client, score_token):
    assert get_scores(client, score_token)['exploitation'] == 0.0


def test_exploit_fires_after_successful_login_and_dashboard_view(client, score_token):
    submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    client.get('/dev/dashboard')
    assert get_scores(client, score_token)['exploitation'] == 2


def test_exploit_does_not_fire_on_failed_login_alone(client, score_token):
    submit_login(client, TARGET_USERNAME, 'wrong-password')
    assert get_scores(client, score_token)['exploitation'] == 0.0


def test_exploit_does_not_fire_without_visiting_dashboard(client, score_token):
    submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    assert get_scores(client, score_token)['exploitation'] == 0.0


def test_all_four_metrics_can_be_at_max_in_one_session(client, score_token):
    client.get('/')
    client.get('/about')
    client.get('/team')
    client.get('/contact')
    for _ in range(5):
        submit_login(client, TARGET_USERNAME, 'wrong-password')
    submit_login(client, TARGET_USERNAME, REAL_PASSWORD)
    client.get('/dev/dashboard')

    scores = get_scores(client, score_token)
    assert scores['exploration'] == 2
    assert scores['reconnaissance'] == 2
    assert scores['vulnerability_detection'] == 2
    assert scores['exploitation'] == 2
