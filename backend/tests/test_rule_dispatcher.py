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



def test_frozen_linux_rule_ids_are_unique_and_lin006_is_inactive():
    from app.analysis.linux_ssh_bruteforce_rule import RULE_ID as lin001
    from app.analysis.linux_ssh_failed_success_rule import RULE_ID as lin002
    from app.analysis.linux_account_lifecycle_rule import RULE_ID as lin003
    from app.analysis.linux_privileged_group_rule import RULE_ID as lin004
    from app.analysis.linux_sudo_rule import RULE_ID as lin005

    active = (lin001, lin002, lin003, lin004, lin005)

    assert active == (
        "RULE-LIN-001",
        "RULE-LIN-002",
        "RULE-LIN-003",
        "RULE-LIN-004",
        "RULE-LIN-005",
    )
    assert len(set(active)) == len(active)
    assert "RULE-LIN-006" not in active
