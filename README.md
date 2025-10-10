## gs_custom_csrf — ZAP Jython CSRF Rule

Defensive-only CSRF detection rule for OWASP ZAP (2.x) written in Jython (Python 2.7). It combines passive heuristics with optional active replay checks to detect Anti-CSRF weaknesses.

- Alert name: `gs_custom_csrf`
- CWE: 352
- WASC: 8

### What it detects

- Missing anti-CSRF tokens on state-changing requests (POST/PUT/DELETE/PATCH).
- Tokens only present as cookies (no per-request token/header).
- Tokens passed via GET query parameters (unsafe).
- Static/predictable tokens across responses.
- Tokens not tied to session (same token across different sessions).
- Optional active replay:
  - Replays request with tokens removed or corrupted; if accepted, raises HIGH risk, HIGH confidence.

### Files

- `gs_custom_csrf.py` — the Jython rule.
- `test_server/app.py` — Flask test server with vulnerable and secure endpoints.
- `tests/run_tests.py` — requests-based test runner to demonstrate expected outcomes.
- `examples/requests_samples/` — raw request/response samples for manual testing.

### Install into ZAP

1. Ensure ZAP 2.x and Jython scripting support are enabled.
2. In ZAP, go to Scripts tab → Load.
3. Script Type: select “Passive Scan Rules” (or “HTTP Sender” if you prefer to adapt).
4. Language: Jython.
5. Name: `gs_custom_csrf`.
6. Load `gs_custom_csrf.py`.

Note: This script is implemented as a Passive Scan Rule with optional active replay. Passive rules normally should not send requests; replay is controlled via a toggle.

### Configuration via ScriptVars

You can override defaults at runtime using ZAP’s Script Variables (Tools → Options → Scripts → Script Vars, or via the Scripting Console):

- `gs_csrf_MAX_SAMPLES` (int, default 5): samples used for stability checks.
- `gs_csrf_ACTIVE_CHECKS` (bool, default true): enable/disable active replay tests.
- `gs_csrf_REPLAY_TIMEOUT` (int ms, default 3000): soft timeout budget for replay.
- `gs_csrf_VERBOSE_LOGGING` (bool, default false): verbose debug logging.

Example (Jython console):
```python
from org.zaproxy.zap.extension.script import ScriptVars
ScriptVars.setGlobalVar("gs_csrf_ACTIVE_CHECKS", "false")
ScriptVars.setGlobalVar("gs_csrf_VERBOSE_LOGGING", "true")
```

### Running the test server

1. Create and activate a Python 3 venv (for the test server only):
```bash
python3 -m venv venv
. venv/bin/activate
pip install flask requests
python test_server/app.py
```
2. The server listens on `http://127.0.0.1:5000`.

### Running the tests

With the server running:

```bash
python tests/run_tests.py
```

You should see outputs like:
- EXPECT: gs_custom_csrf HIGH - missing token detected on /vuln/no_token
- EXPECT: gs_custom_csrf LOW/MEDIUM - static token suspicion on /vuln/static_token; HIGH if replay accepted
- EXPECT: gs_custom_csrf MEDIUM - cookie-only CSRF on /vuln/cookie_only
- EXPECT: gs_custom_csrf MEDIUM - token in GET on /vuln/action_with_token_in_get
- EXPECT: NO gs_custom_csrf on /secure/per_request_token
- EXPECT: NO gs_custom_csrf on /secure/token_in_header
- EXPECT: gs_custom_csrf LOW - token reused across sessions on /edge/token_same_across_sessions

To test with ZAP:
- Proxy your browser or the test runner through ZAP (e.g., `HTTP_PROXY=http://127.0.0.1:8080`).
- Visit each endpoint or run the tests through the proxy.
- Ensure the passive scanner is enabled. If you want the active replay confirmations, keep `gs_csrf_ACTIVE_CHECKS=true`.

### Notes on ZAP API compatibility

- The script uses `HttpMessage.cloneRequest()` which is available in ZAP 2.9+. If your ZAP version lacks this, the script falls back to reconstructing from header/body strings.
- Passive scan scripts typically should not perform active requests. This script only does so if `gs_csrf_ACTIVE_CHECKS=true`. If your environment forbids actives in passive scripts, set it to false or port this logic into an “Active Scan Rule” script using the same helper functions.

### Ethics and safety

This is for defensive testing on assets you own or have explicit permission to test. Unauthorized scanning can be illegal and unethical.

### Tuning and false positives

- Static token suspicion may be noisy on apps that issue long-lived per-session tokens; enable active replay to confirm.
- Cookie-only detections may be a false positive if robust SameSite enforcement and server-side binding exist; review context.
- GET token warnings will trigger for any GET form carrying a token; validate whether it’s truly state-changing.

### References

- OWASP CSRF Prevention Cheat Sheet
- OWASP ZAP Scripting Guide


