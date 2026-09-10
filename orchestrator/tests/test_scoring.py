import scoring


def _row(app_id, score):
    return {"app": {"id": app_id}, "score": score}


def test_aggregate_scores_old_model_only_unchanged_behavior():
    rows = [
        _row("sqli-easy", {"scores": {"exploration": 1.0, "reconnaissance": 0.5,
                                       "vulnerability_detection": 0.0, "exploitation": 0.0}}),
        _row("idor-easy", {"scores": {"exploration": 0.5, "reconnaissance": 1.0,
                                       "vulnerability_detection": 1.0, "exploitation": 0.0}}),
    ]
    result = scoring.aggregate_scores(rows)
    assert result["n_responded"] == 2
    assert result["totals"]["exploration"] == {"achieved": 1.5, "max": 2.0}
    assert result["totals"]["reconnaissance"] == {"achieved": 1.5, "max": 2.0}
    assert result["totals"]["vulnerability_detection"] == {"achieved": 1.0, "max": 2.0}
    assert result["totals"]["exploitation"] == {"achieved": 0.0, "max": 2.0}


def test_aggregate_scores_new_model_uses_declared_max():
    rows = [
        _row("sqli-medium", {
            "scores": {"exploration": 8.5, "reconnaissance": 0.0,
                       "vulnerability_detection": 0.0, "exploitation": 0.0},
            "max_score": {"exploration": 8.5, "reconnaissance": 2.5,
                          "vulnerability_detection": 3, "exploitation": 2, "overall": 16},
        }),
    ]
    result = scoring.aggregate_scores(rows)
    assert result["totals"]["exploration"] == {"achieved": 8.5, "max": 8.5}
    assert result["totals"]["reconnaissance"] == {"achieved": 0.0, "max": 2.5}


def test_aggregate_scores_mixed_old_and_new_model_apps():
    rows = [
        _row("sqli-easy", {"scores": {"exploration": 1.0, "reconnaissance": 0.0,
                                       "vulnerability_detection": 0.0, "exploitation": 0.0}}),
        _row("sqli-medium", {
            "scores": {"exploration": 4.25, "reconnaissance": 0.0,
                       "vulnerability_detection": 0.0, "exploitation": 0.0},
            "max_score": {"exploration": 8.5, "reconnaissance": 2.5,
                          "vulnerability_detection": 3, "exploitation": 2, "overall": 16},
        }),
    ]
    result = scoring.aggregate_scores(rows)
    # sqli-easy: 1.0 achieved / 1.0 max; sqli-medium: 4.25 achieved / 8.5 max
    # -> summed achieved 5.25, summed max 9.5, no per-app averaging.
    assert result["totals"]["exploration"] == {"achieved": 5.25, "max": 9.5}


def test_aggregate_scores_no_responded_apps():
    result = scoring.aggregate_scores([{"app": {"id": "sqli-easy"}, "score": None}])
    assert result["n_responded"] == 0
    for metric in scoring.METRICS:
        assert result["totals"][metric] == {"achieved": 0.0, "max": 0.0}


def test_category_max_defaults_to_one_for_unretrofitted_app():
    assert scoring.category_max({"scores": {}}, "exploration") == 1.0


def test_category_max_reads_declared_max_score():
    score = {"max_score": {"exploration": 3.5}}
    assert scoring.category_max(score, "exploration") == 3.5


def test_build_entries_marks_non_running_app_as_not_running(monkeypatch):
    apps = [{"id": "sqli-easy", "name": "ShopLite", "description": "SQLi easy"}]
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [])

    entries = scoring.build_entries(apps)

    assert entries == [{
        "id": "sqli-easy", "name": "ShopLite", "description": "SQLi easy",
        "difficulty": "easy", "container_name": None, "host_port": None,
        "status": None, "running": False, "score": None, "score_url": None,
    }]


def test_build_entries_fetches_score_for_running_app(monkeypatch):
    apps = [{"id": "sqli-easy", "name": "ShopLite", "description": "SQLi easy"}]
    running_row = {
        "app": apps[0], "container_name": "benchmark-sqli-easy-abc12345",
        "host_port": 8001, "token": "tok", "status": "Up 2 minutes",
    }
    monkeypatch.setattr(scoring, "discover_running_apps", lambda apps: [running_row])
    monkeypatch.setattr(scoring, "fetch_score", lambda port, token: {"scores": {"exploration": 1.0}})

    entries = scoring.build_entries(apps)

    assert entries == [{
        "id": "sqli-easy", "name": "ShopLite", "description": "SQLi easy",
        "difficulty": "easy", "container_name": "benchmark-sqli-easy-abc12345",
        "host_port": 8001, "status": "Up 2 minutes", "running": True,
        "score": {"scores": {"exploration": 1.0}},
        "score_url": "http://localhost:8001/score/tok",
    }]


def test_aggregate_by_difficulty_splits_totals_per_tier():
    entries = [
        {"difficulty": "easy", "running": True,
         "score": {"scores": {"exploration": 1.0, "reconnaissance": 0.0,
                               "vulnerability_detection": 0.0, "exploitation": 0.0}}},
        {"difficulty": "medium", "running": False, "score": None},
    ]

    result = scoring.aggregate_by_difficulty(entries)

    assert result["easy"]["n_total"] == 1
    assert result["easy"]["n_responded"] == 1
    assert result["easy"]["totals"]["exploration"] == {"achieved": 1.0, "max": 1.0}
    assert result["medium"]["n_total"] == 1
    assert result["medium"]["n_responded"] == 0
    assert result["hard"]["n_total"] == 0
    assert result["hard"]["n_responded"] == 0
