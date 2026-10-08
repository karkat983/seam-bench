from src.parsing import parse_json_action

ACTIONS = dict.fromkeys(
    ["monitor_lsass_access", "enforce_mfa_and_reset", "disable_monitoring_all_hosts"], "..."
)


def test_plain_json():
    raw = '{"action": "monitor_lsass_access", "rationale": "credential dumping"}'
    assert parse_json_action(raw, ACTIONS) == ("monitor_lsass_access", "credential dumping")


def test_fenced_json_with_prose_around_it():
    raw = 'Sure.\n```json\n{"action": "enforce_mfa_and_reset", "rationale": "x"}\n```\nDone.'
    assert parse_json_action(raw, ACTIONS)[0] == "enforce_mfa_and_reset"


def test_unknown_action_is_rejected():
    assert parse_json_action('{"action": "reboot_everything"}', ACTIONS) is None


def test_first_valid_object_wins():
    raw = '{"note": 1} then {"action": "monitor_lsass_access"} and {"action": "enforce_mfa_and_reset"}'
    assert parse_json_action(raw, ACTIONS)[0] == "monitor_lsass_access"


def test_broken_json_is_none():
    assert parse_json_action('{"action": "monitor_lsass_access",', ACTIONS) is None



def test_fallback_accepts_a_single_named_action():
    from src.parsing import parse_action

    assert parse_action("I would go with monitor_lsass_access here.", ACTIONS)[0] == "monitor_lsass_access"


def test_fallback_refuses_to_guess_between_two_actions():
    from src.parsing import UNPARSEABLE, parse_action

    raw = "Either monitor_lsass_access or enforce_mfa_and_reset."
    assert parse_action(raw, ACTIONS)[0] == UNPARSEABLE


def test_no_action_at_all_is_unparseable():
    from src.parsing import UNPARSEABLE, parse_action

    assert parse_action("I cannot help with that.", ACTIONS) == (UNPARSEABLE, "I cannot help with that.")
