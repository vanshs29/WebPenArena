from conftest import _preview


def test_expr_evaluated_confirms_serverside_eval(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, "{{7*6}}")
        assert "recon_expr_evaluated" in get_fired_events(get_db(app))


def test_expr_not_evaluated_when_absent(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, "just text")
        assert "recon_expr_evaluated" not in get_fired_events(get_db(app))


def test_expr_evaluated_checks_the_correct_product(client, app):
    from app.db import get_db
    from app.scoring import get_fired_events

    with app.app_context():
        _preview(client, "{{9*9}}")
        assert "recon_expr_evaluated" in get_fired_events(get_db(app))
