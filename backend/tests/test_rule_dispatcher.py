from app.analysis.rule_dispatcher import RuleRunner, run_registered_rules


def test_dispatcher_runs_rules_independently():
    calls = []

    def broken():
        calls.append("broken")
        raise RuntimeError("test failure")

    def healthy():
        calls.append("healthy")
        return {"events_processed": 1}

    outcomes = run_registered_rules((
        RuleRunner("RULE-TEST-FAIL", broken),
        RuleRunner("RULE-TEST-OK", healthy),
    ))

    assert calls == ["broken", "healthy"]
    assert isinstance(outcomes[0].error, RuntimeError)
    assert outcomes[0].result is None
    assert outcomes[1].error is None
    assert outcomes[1].result == {"events_processed": 1}


def test_dispatcher_does_not_execute_duplicate_rule_id():
    import pytest

    with pytest.raises(ValueError, match="unique"):
        run_registered_rules((
            RuleRunner("RULE-TEST-1", lambda: {}),
            RuleRunner("RULE-TEST-1", lambda: {}),
        ))
