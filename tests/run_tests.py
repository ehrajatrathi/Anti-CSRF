# Lightweight test runner using requests
# Spins through endpoints and simulates active replay logic akin to the ZAP script.
# This does NOT call ZAP API directly to keep setup minimal.
#
# EXPECT results are printed for each test case.

import requests

BASE = "http://127.0.0.1:5000"

def new_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "csrf-tester"})
    return s

def get_form_token(html, name_hint="csrf"):
    import re
    # simple parser
    for m in re.findall(r'<input[^>]*type=["\']?hidden["\']?[^>]*>', html, re.I):
        nm = re.search(r'name=["\']([^"\']+)["\']', m, re.I)
        val = re.search(r'value=["\']([^"\']*)["\']', m, re.I)
        if nm:
            n = nm.group(1)
            if name_hint in n.lower():
                return n, (val.group(1) if val else "")
    return None, None

def get_meta_token(html):
    import re
    m = re.search(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None

def test_no_token():
    print("EXPECT: gs_custom_csrf HIGH - missing token detected on /vuln/no_token")
    s = new_session()
    s.get(BASE + "/vuln/no_token")
    r = s.post(BASE + "/vuln/no_token", data={"foo": "bar"})
    print("POST status:", r.status_code, "(should be 200)")

def test_static_token():
    print("EXPECT: gs_custom_csrf LOW/MEDIUM - static token suspicion on /vuln/static_token; HIGH if replay accepted")
    s = new_session()
    r1 = s.get(BASE + "/vuln/static_token")
    _, t1 = get_form_token(r1.text)
    r2 = s.get(BASE + "/vuln/static_token")
    _, t2 = get_form_token(r2.text)
    print("Tokens observed:", t1, t2, "(should be same)")
    # Replay with missing token
    r3 = s.post(BASE + "/vuln/static_token", data={"foo": "bar"})
    print("Replay missing token status:", r3.status_code, "(should be 200)")

def test_cookie_only():
    print("EXPECT: gs_custom_csrf MEDIUM - cookie-only CSRF on /vuln/cookie_only")
    s = new_session()
    s.get(BASE + "/vuln/cookie_only")
    r = s.post(BASE + "/vuln/cookie_only", data={"x": "1"})
    print("POST status:", r.status_code, "(should be 200)")

def test_token_in_get():
    print("EXPECT: gs_custom_csrf MEDIUM - token in GET on /vuln/action_with_token_in_get")
    s = new_session()
    r = s.get(BASE + "/vuln/action_with_token_in_get")
    print("GET status:", r.status_code, "(should be 200)")
    # Trigger the GET action
    r2 = s.get(BASE + "/vuln/do_get_action?csrf_token=STATIC-TOKEN-12345")
    print("Do GET action status:", r2.status_code, "(should be 200)")

def test_secure_per_request_token():
    print("EXPECT: NO gs_custom_csrf on /secure/per_request_token")
    s = new_session()
    r = s.get(BASE + "/secure/per_request_token")
    name, token = get_form_token(r.text)
    # First post with provided token
    r2 = s.post(BASE + "/secure/per_request_token", data={name: token})
    # Replay without token should be rejected
    r3 = s.post(BASE + "/secure/per_request_token", data={"foo": "bar"})
    print("First POST status:", r2.status_code, "(should be 200)")
    print("Replay without token status:", r3.status_code, "(should be 403)")

def test_secure_token_in_header():
    print("EXPECT: NO gs_custom_csrf on /secure/token_in_header")
    s = new_session()
    r = s.get(BASE + "/secure/token_in_header")
    mtok = get_meta_token(r.text)
    # With header -> OK
    r2 = s.post(BASE + "/secure/token_in_header", data={"foo": "bar"}, headers={"X-CSRF-Token": mtok})
    # Without header -> reject
    r3 = s.post(BASE + "/secure/token_in_header", data={"foo": "bar"})
    print("With header status:", r2.status_code, "(should be 200)")
    print("Without header status:", r3.status_code, "(should be 403)")

def test_edge_same_token_across_sessions():
    print("EXPECT: gs_custom_csrf LOW - token reused across sessions on /edge/token_same_across_sessions")
    s1 = new_session()
    s2 = new_session()
    t1 = get_form_token(s1.get(BASE + "/edge/token_same_across_sessions").text)[1]
    t2 = get_form_token(s2.get(BASE + "/edge/token_same_across_sessions").text)[1]
    print("Tokens across sessions:", t1, t2, "(should be same)")

if __name__ == "__main__":
    print("Running CSRF detection demo tests against", BASE)
    test_no_token()
    print("---")
    test_static_token()
    print("---")
    test_cookie_only()
    print("---")
    test_token_in_get()
    print("---")
    test_secure_per_request_token()
    print("---")
    test_secure_token_in_header()
    print("---")
    test_edge_same_token_across_sessions()


