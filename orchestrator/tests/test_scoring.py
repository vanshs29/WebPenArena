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
