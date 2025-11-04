# Flask test server to demonstrate CSRF detections (with login)
# IMPORTANT: Defensive/testing use only. Do not expose publicly.
from flask import Flask, request, make_response, jsonify, redirect
import os
import uuid
import json  # added for safe JS payload embedding in reflected pages

app = Flask(__name__)
app.secret_key = "dev-secret"

# In-memory stores for demo; do NOT use in production
STATIC_TOKEN = "STATIC-TOKEN-12345"
SESSION_TOKENS = {}          # session_id -> token (per-request)
SESSION_HEADER_TOKENS = {}   # session_id -> header token
SESSION_NONCES = {}          # session_id -> set(valid nonces)
SESSIONS = {}                # session_id -> username (simple auth map)


def ensure_session():
    sid = request.cookies.get("sessionid")
    if not sid:
        sid = str(uuid.uuid4())
    resp = make_response()
    resp.set_cookie("sessionid", sid, httponly=True, samesite="Lax")
    return sid, resp


def set_csrf_cookie_only(resp):
    # cookie-only anti-CSRF (vulnerable)
    resp.set_cookie("csrftoken", "COOKIE-ONLY-TOKEN", httponly=False, samesite="Lax")
    return resp


def issue_per_request_token(sessionid):
    # Return a new per-request token tied to session for /secure/per_request_token
    token = str(uuid.uuid4())
    SESSION_TOKENS[sessionid] = token
    return token


def issue_header_token(sessionid):
    token = str(uuid.uuid4())
    SESSION_HEADER_TOKENS[sessionid] = token
    return token


def issue_nonce(sessionid):
    """Issue a single-use nonce tied to the session. Stored until consumed."""
    n = str(uuid.uuid4())
    s = SESSION_NONCES.get(sessionid)
    if s is None:
        s = set()
        SESSION_NONCES[sessionid] = s
    s.add(n)
    return n


def consume_nonce(sessionid, nonce):
    """Return True and remove nonce if present. False if not present (invalid/replayed)."""
    s = SESSION_NONCES.get(sessionid)
    if not s:
        return False
    if nonce in s:
        s.remove(nonce)
        return True
    return False


@app.route("/")
def index():
    sid, resp = ensure_session()
    user = SESSIONS.get(sid)
    username_html = f"<p>Logged in as: <strong>{user}</strong></p>" if user else "<p>Not logged in</p>"
    html = f"""<html><body>
    <h3>CSRF test server</h3>
    {username_html}
    <ul>
      <li><a href="/login">/login</a></li>
      <li><a href="/vuln/no_token">/vuln/no_token</a></li>
      <li><a href="/vuln/static_token">/vuln/static_token</a></li>
      <li><a href="/vuln/cookie_only">/vuln/cookie_only</a></li>
      <li><a href="/vuln/action_with_token_in_get">/vuln/action_with_token_in_get</a></li>
      <li><a href="/secure/per_request_token">/secure/per_request_token</a></li>
      <li><a href="/secure/token_in_header">/secure/token_in_header</a></li>
      <li><a href="/edge/token_same_across_sessions">/edge/token_same_across_sessions</a></li>
      <li><a href="/neg/token_present">/neg/token_present (negative test: token present & rotating)</a></li>
      <li><a href="/neg/token_nonce">/neg/token_nonce (negative test: single-use nonce)</a></li>
      <li><a href="/dangerous/js_eval_function">/dangerous/js_eval_function (dangerous JS tokens)</a></li>
      <li><a href="/dangerous/js_dom_injection">/dangerous/js_dom_injection (reflect payload)</a></li>
      <li><a href="/dangerous/js_timers_windowopen">/dangerous/js_timers_windowopen (timers & window.open)</a></li>
      <li><a href="/logout">/logout</a></li>
    </ul>
    </body></html>"""
    resp.set_data(html)
    return resp


# Simple login page for testing authenticated flows
# Credentials (demo): username: user  password: pass
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'GET':
        sid, resp = ensure_session()
        html = '''<html><body>
            <h3>Login (demo)</h3>
            <form method="POST" action="/login">
                <label>Username: <input type="text" name="username"/></label><br/>
                <label>Password: <input type="password" name="password"/></label><br/>
                <button type="submit">Login</button>
            </form>
            <p>Demo creds: <strong>user</strong> / <strong>pass</strong></p>
            <p>After login you'll have a session cookie; use it to test authenticated CSRF endpoints.</p>
            </body></html>'''
        resp.set_data(html)
        return resp

    # POST -> perform simple auth and set session mapping
    username = request.form.get('username')
    password = request.form.get('password')
    # Very simple demo check
    if username == 'user' and password == 'pass':
        sid = request.cookies.get('sessionid')
        if not sid:
            sid = str(uuid.uuid4())
        # map session -> user
        SESSIONS[sid] = username
        # issue header & per-request tokens for convenience
        issue_header_token(sid)
        issue_per_request_token(sid)
        resp = make_response(redirect('/'))
        resp.set_cookie('sessionid', sid, httponly=True, samesite='Lax')
        return resp

    # Invalid creds -> show message
    sid, resp = ensure_session()
    resp.set_data('<html><body>Invalid credentials. <a href="/login">Try again</a></body></html>')
    return resp


@app.route('/logout')
def logout():
    sid = request.cookies.get('sessionid')
    if sid:
        SESSIONS.pop(sid, None)
        SESSION_TOKENS.pop(sid, None)
        SESSION_HEADER_TOKENS.pop(sid, None)
        SESSION_NONCES.pop(sid, None)
    resp = make_response(redirect('/'))
    resp.set_cookie('sessionid', '', expires=0)
    return resp


# 1) POST /vuln/no_token — no CSRF token required (vulnerable)
@app.route("/vuln/no_token", methods=["GET", "POST"])
def vuln_no_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Vuln: no token</h3>
        <form method="POST" action="/vuln/no_token">
            <input type="hidden" name="not_csrf" value="x"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        return resp
    # POST: always accept
    return "OK - no token required", 200


# 2) POST /vuln/static_token — static token (vulnerable)
@app.route("/vuln/static_token", methods=["GET", "POST"])
def vuln_static_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Vuln: static token</h3>
        <form method="POST" action="/vuln/static_token">
            <input type="hidden" name="csrf_token" value="%s"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % STATIC_TOKEN
        resp.set_data(html)
        return resp
    # POST: accept any value, including missing or invalid (vulnerable by design)
    return "OK - static token ignored", 200


# 3) POST /vuln/cookie_only — cookie-only CSRF (vulnerable)
@app.route("/vuln/cookie_only", methods=["GET", "POST"])
def vuln_cookie_only():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Vuln: cookie only</h3>
        <form method="POST" action="/vuln/cookie_only">
            <input type="hidden" name="foo" value="bar"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        set_csrf_cookie_only(resp)
        return resp
    # POST: accept without any token
    return "OK - cookie only", 200


# 4) GET /vuln/action_with_token_in_get — token in query for a state-change (vulnerable)
@app.route("/vuln/action_with_token_in_get", methods=["GET"])
def vuln_token_in_get():
    sid, resp = ensure_session()
    html = """<html><body>
    <h3>Vuln: token in GET</h3>
    <form method="GET" action="/vuln/do_get_action?csrf_token=%s">
        <button type="submit">Do GET Action</button>
    </form>
    </body></html>""" % STATIC_TOKEN
    resp.set_data(html)
    return resp


@app.route("/vuln/do_get_action", methods=["GET"])
def vuln_do_get_action():
    # Pretend it changes state via GET (bad)
    return "OK - GET changed state", 200


# 5) POST /secure/per_request_token — correct per-request token (secure)
@app.route("/secure/per_request_token", methods=["GET", "POST"])
def secure_per_request_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_per_request_token(sid)
        html = """<html><body>
        <h3>Secure: per request token</h3>
        <form method="POST" action="/secure/per_request_token">
            <input type="hidden" name="csrf_token" value="%s"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % token
        resp.set_data(html)
        return resp
    # POST: require exact token
    form_token = request.form.get("csrf_token")
    expected = SESSION_TOKENS.get(sid)
    if form_token and expected and form_token == expected:
        # Accept and rotate token to prevent replay
        SESSION_TOKENS[sid] = str(uuid.uuid4())
        return "OK - valid token", 200
    return "Forbidden - invalid/missing token", 403


# 6) POST /secure/token_in_header — token required in header and tied to session (secure)
@app.route("/secure/token_in_header", methods=["GET", "POST"])
def secure_token_in_header():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_header_token(sid)
        # Provide token via JS meta tag for client to put into header
        html = """<html><head>
        <meta name="csrf-token" content="%s"/>
        </head><body>
        <h3>Secure: token in header</h3>
        <form method="POST" action="/secure/token_in_header">
            <input type="hidden" name="foo" value="bar"/>
            <p>Client must send X-CSRF-Token header with value from meta tag.</p>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % token
        resp.set_data(html)
        return resp
    # POST: require header token bound to session
    hdr = request.headers.get("X-CSRF-Token")
    expected = SESSION_HEADER_TOKENS.get(sid)
    if hdr and expected and hdr == expected:
        # rotate
        SESSION_HEADER_TOKENS[sid] = str(uuid.uuid4())
        return "OK - header token", 200
    return "Forbidden - missing/invalid header token", 403


# 7) Optional: POST /edge/token_same_across_sessions — token not tied to session (vulnerable)
@app.route("/edge/token_same_across_sessions", methods=["GET", "POST"])
def edge_same_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        # Emit same token for everyone, across sessions
        html = """<html><body>
        <h3>Edge: same token across sessions</h3>
        <form method="POST" action="/edge/token_same_across_sessions">
            <input type="hidden" name="csrf_token" value="%s"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % STATIC_TOKEN
        resp.set_data(html)
        return resp
    # Accept any token (vulnerable)
    return "OK - not tied to session", 200


# -----------------------
# NEGATIVE TESTS (secure)
# -----------------------

# NEG 1) /neg/token_present — per-request token (server validates & rotates)
@app.route("/neg/token_present", methods=["GET", "POST"])
def neg_token_present():
    sid, resp = ensure_session()
    if request.method == "GET":
        # issue a per-request token that must be returned in the POST form
        token = issue_per_request_token(sid)
        html = f"""<html><body>
        <h3>Neg Test: token present & rotating</h3>
        <form method="POST" action="/neg/token_present">
            <input type="hidden" name="csrf_token" value="{token}"/>
            <button type="submit">Submit</button>
        </form>
        <p>This endpoint issues a fresh token per GET and requires it on POST. Token rotates on success.</p>
        </body></html>"""
        resp.set_data(html)
        return resp

    # POST: require exact token and rotate on success
    form_token = request.form.get("csrf_token")
    expected = SESSION_TOKENS.get(sid)
    if form_token and expected and form_token == expected:
        # rotate to a new token so token is not static
        SESSION_TOKENS[sid] = str(uuid.uuid4())
        return "OK - valid rotating token (negative test)", 200
    return "Forbidden - invalid/missing token", 403


# NEG 2) /neg/token_nonce — single-use nonce (server consumes nonce once used)
@app.route("/neg/token_nonce", methods=["GET", "POST"])
def neg_token_nonce():
    sid, resp = ensure_session()
    if request.method == "GET":
        # issue a single-use nonce and embed it in the form
        nonce = issue_nonce(sid)
        html = f"""<html><body>
        <h3>Neg Test: single-use nonce</h3>
        <form method="POST" action="/neg/token_nonce">
            <input type="hidden" name="csrf_nonce" value="{nonce}"/>
            <button type="submit">Submit</button>
        </form>
        <p>This endpoint issues a unique nonce each GET; once POSTed the nonce is consumed.</p>
        </body></html>"""
        resp.set_data(html)
        return resp

    # POST: check and consume the nonce
    form_nonce = request.form.get("csrf_nonce")
    if form_nonce and consume_nonce(sid, form_nonce):
        return "OK - valid single-use nonce (negative test)", 200
    return "Forbidden - invalid/missing/used nonce", 403


# -----------------------
# DANGEROUS JS TEST ENDPOINTS (added)
# -----------------------
# Defensive/testing use only. Do NOT expose these pages publicly.

@app.route("/dangerous/js_eval_function", methods=["GET"])
def dangerous_js_eval_function():
    sid, resp = ensure_session()
    # contains uses of eval() and the Function constructor
    html = """<html><body>
    <h3>Dangerous JS: eval() & Function()</h3>
    <p>Test cases visible in page source and executed by browser (for local testing only).</p>

    <script>
    // Example 1: direct eval()
    var code = "console.log('EVAL: executed');";
    // NOTE: Uncommenting the next line will execute the eval in the client.
    // eval(code);

    // Example 2: Function constructor
    var fnCode = "return 'Function: executed';";
    // var f = new Function(fnCode);
    // console.log(f());

    // Example 3: eval used via setTimeout string (legacy bad pattern)
    // setTimeout("console.log('setTimeout string eval')", 1000);
    </script>

    <p>Source contains the literal tokens: <code>eval</code>, <code>Function</code>, <code>setTimeout(\"...\")</code></p>
    </body></html>"""
    resp.set_data(html)
    return resp


@app.route("/dangerous/js_dom_injection", methods=["GET", "POST"])
def dangerous_js_dom_injection():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Dangerous JS: DOM injection (innerHTML, outerHTML, document.write, $sce.trustAsHtml)</h3>
        <p>POST some HTML (e.g. <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>) to reflect it back into the page to test detectors.</p>
        <form method="POST" action="/dangerous/js_dom_injection">
            <label>Payload: <input type="text" name="payload" size="80" value="&lt;script&gt;console.log('xss')&lt;/script&gt;"/></label>
            <button type="submit">Reflect payload</button>
        </form>
        <hr/>
        <div id="reflect-server">No payload posted yet.</div>

        <!-- Example static uses so scanners find tokens in source -->
        <script>
        // This is an intentionally dangerous pattern if 'userHtml' is untrusted.
        // Example tokens: innerHTML, outerHTML, document.write
        var example = '<div>example</div>';
        // document.getElementById('reflect-server').innerHTML = example; // unsafe if example came from user
        // document.write('<p>document.write example</p>');
        // document.getElementById('reflect-server').outerHTML = '<section id="reflect-server">replaced</section>';
        </script>

        <!-- AngularJS example token (non-executing): $sce.trustAsHtml -->
        <script>
        // In AngularJS you'd call $sce.trustAsHtml(userHtml) to bypass Angular sanitization.
        // This token is useful for scanners: $sce.trustAsHtml
        </script>
        </body></html>"""
        resp.set_data(html)
        return resp

    # POST: reflect payload back into page using innerHTML and document.write examples
    payload = request.form.get("payload", "")
    sid, resp = ensure_session()  # ensure cookie still set on response
    # Show two reflection methods: one using innerHTML, one using document.write inside returned HTML
    # Use json.dumps to safely embed the payload string into the <script> literal
    escaped_payload_for_script = json.dumps(payload)
    html = f"""<html><body>
    <h3>Dangerous JS: reflected payload</h3>
    <p>Payload you posted (raw):</p>
    <pre>{payload}</pre>

    <h4>innerHTML reflection (unsafe)</h4>
    <div id="vuln_inner">{payload}</div>

    <h4>document.write reflection (unsafe)</h4>
    <script>
    // This document.write will write the payload string (as-is) when the browser executes it.
    document.write({escaped_payload_for_script});
    </script>

    <p><a href="/dangerous/js_dom_injection">Back</a></p>
    </body></html>"""
    resp.set_data(html)
    return resp


@app.route("/dangerous/js_timers_windowopen", methods=["GET"])
def dangerous_js_timers_windowopen():
    sid, resp = ensure_session()
    # contains setTimeout with function and string, setInterval, and window.open examples
    html = """<html><body>
    <h3>Dangerous JS: timers & window.open</h3>
    <p>Contains examples of <code>setTimeout</code>, <code>setInterval</code> and <code>window.open</code> tokens.</p>

    <button id="openBtn">Open popup (window.open)</button>
    <button id="timerBtn">Start timer (setInterval)</button>

    <script>
    document.getElementById('openBtn').addEventListener('click', function(){
        // Example of window.open usage (some scanners look for this)
        // var w = window.open('about:blank', '_blank', 'noopener');
        // w && w.document && w.document.write('<p>opened</p>');
    });

    document.getElementById('timerBtn').addEventListener('click', function(){
        // setInterval and setTimeout tokens present
        // var id = setInterval(function(){ console.log('tick'); }, 1000);
        // setTimeout(function(){ clearInterval(id); console.log('cleared'); }, 5000);
    });

    // legacy dangerous pattern: setTimeout with string -> triggers eval-like behavior
    // setTimeout("alert('timeout-eval')", 1000);
    </script>

    <p>Source contains literal tokens: <code>setTimeout</code>, <code>setInterval</code>, <code>window.open</code>.</p>
    </body></html>"""
    resp.set_data(html)
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
