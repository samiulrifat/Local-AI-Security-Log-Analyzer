from app.replies import check_events, parse_json


def test_normal_json():
    assert parse_json('{"events":[]}') == {"events": []}


def test_code_fences_and_think_tags():
    assert parse_json('<think>hmm</think>```json\n{"events":[]}\n```') == {"events": []}


def test_cut_off_reply_keeps_complete_items():
    text = '{"events":[{"id":"1.1.1.1","lines":[1]},{"id":"2.2.2.2","lin'
    assert parse_json(text) == {"events": [{"id": "1.1.1.1", "lines": [1]}]}


def test_cut_off_inside_string():
    text = '{"events":[{"id":"1.1.1.1","reason":"ok"},{"id":"2.2.2.2","reason":"never fin'
    assert len(parse_json(text)["events"]) == 1


def test_garbage_does_not_crash():
    for text in ["", "sorry I can't", "}{", '{"a":', "[1,2,3]", None]:
        assert parse_json(text) is None


LINES = {"1.1.1.1": [5, 6], "2.2.2.2": [7]}


def entry(line, status=403, path="/.env", text="", method="GET"):
    return {"line": line, "status": status, "path": path, "auth": None, "method": method,
            "text": text or f"L{line} {method} {path} {status}"}


ENTRIES = [entry(5), entry(6), entry(7)]


def test_ids_map_back_to_actors_and_code_picks_the_lines():
    reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": "scanning"}, {"id": "2.2.2.2", "saw": "y", "type": "normal"}]}
    good, rejected = check_events(reply, ENTRIES, LINES)
    assert [(e["actor"], e["lines"], e["reason"]) for e in good] == [("1.1.1.1", [5, 6], "x")]
    assert rejected == 0


def test_only_lines_that_fit_the_claim_become_evidence():
    entries = [entry(5, status=401, path="/login"), entry(6, status=200, path="/login"), entry(7)]
    reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": "failed_login"}]}
    assert check_events(reply, entries, LINES)[0][0]["lines"] == [5]


def test_unknown_id_is_rejected():
    reply = {"groups": [{"id": "9.9.9.9", "saw": "x", "type": "scanning"}]}
    assert check_events(reply, ENTRIES, LINES) == ([], 1)


def test_odd_usernames_still_match_the_cleaned_id():
    lines = {'bob "the" admin': [5]}
    reply = {"groups": [{"id": "bob__the__admin", "saw": "x", "type": "scanning"}]}
    assert check_events(reply, [entry(5)], lines)[0][0]["actor"] == 'bob "the" admin'


def test_unknown_type_becomes_other():
    reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": "aliens"}]}
    assert check_events(reply, ENTRIES, LINES)[0][0]["type"] == "other"


def test_answer_about_a_different_ip_is_rejected():
    # the model really did this, it put a note about 45.33.12.9 on another group
    reply = {"groups": [{"id": "1.1.1.1", "saw": "failed ssh logins from 45.33.12.9", "type": "failed_login"}]}
    assert check_events(reply, ENTRIES, LINES) == ([], 1)


def test_claim_has_to_fit_the_line():
    # the real mistake the model made: calling a normal login page view sql injection
    lines = {"1.1.1.1": [39]}
    reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": "sql_injection"}]}
    assert check_events(reply, [entry(39, status=200, path="/login")], lines) == ([], 1)

    entries = [entry(39, status=400, path="/c?search=%27%20OR%201=1--")]
    assert check_events(reply, entries, lines)[0][0]["type"] == "sql_injection"


def test_opening_the_login_page_is_not_a_login():
    # another real one, GET /login 200 kept getting called login_after_failures
    lines = {"1.1.1.1": [18]}
    reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": "login_after_failures"}]}
    assert check_events(reply, [entry(18, status=200, path="/login")], lines) == ([], 1)
    assert check_events(reply, [entry(18, status=200, path="/login", method="POST")], lines)[0]


def test_server_errors_are_not_scanning_or_unauthorized():
    lines = {"1.1.1.1": [1]}
    entries = [entry(1, status=503, path="/api/v1/dashboard")]
    for kind in ("scanning", "unauthorized_access"):
        reply = {"groups": [{"id": "1.1.1.1", "saw": "x", "type": kind}]}
        assert check_events(reply, entries, lines) == ([], 1)


def test_wrong_shapes_do_not_crash():
    for reply in [{"groups": "nope"}, {"groups": [1, None]}, {}, {"groups": [{"id": 1}]}, None]:
        check_events(reply, ENTRIES, LINES)
