# Flask test server to demonstrate CSRF detections (with login)
# IMPORTANT: Defensive/testing use only. Do not expose publicly.
from flask import Flask, request, make_response, jsonify, redirect
import os
import uuid

app = Flask(__name__)
app.secret_key = "dev-secret"

# In-memory stores for demo; do NOT use in production
STATIC_TOKEN = "STATIC-TOKEN-12345"
SESSION_TOKENS = {}          # session_id -> token (per-request)
SESSION_HEADER_TOKENS = {}   # session_id -> header token
SESSION_NONCES = {}          # session_id -> set(valid nonces)
SESSIONS = {}                # session_id -> username (simple auth map)


# -----------------------
# Utility helpers
# -----------------------
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
    token = str(uuid.uuid4())
    SESSION_TOKENS[sessionid] = token
    return token


def issue_header_token(sessionid):
    token = str(uuid.uuid4())
    SESSION_HEADER_TOKENS[sessionid] = token
    return token


def issue_nonce(sessionid):
    n = str(uuid.uuid4())
    s = SESSION_NONCES.get(sessionid)
    if s is None:
        s = set()
        SESSION_NONCES[sessionid] = s
    s.add(n)
    return n


def consume_nonce(sessionid, nonce):
    s = SESSION_NONCES.get(sessionid)
    if not s:
        return False
    if nonce in s:
        s.remove(nonce)
        return True
    return False


# -----------------------
# Index & Login System
# -----------------------
@app.route("/")
def index():
    sid, resp = ensure_session()
    user = SESSIONS.get(sid)
    username_html = f"<p>Logged in as: <strong>{user}</strong></p>" if user else "<p>Not logged in</p>"
    html = f"""<html><body>
    <h3>CSRF Test Server</h3>
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
      <li><a href="/pos/no_token_post">/pos/no_token_post (positive test)</a></li>
      <li><a href="/pos/static_token">/pos/static_token (positive test)</a></li>
      <li><a href="/pos/token_in_get">/pos/token_in_get (positive test)</a></li>
      <li><a href="/neg/token_present">/neg/token_present (negative test)</a></li>
      <li><a href="/neg/token_nonce">/neg/token_nonce (negative test)</a></li>
      <li><a href="/logout">/logout</a></li>
    </ul>
    </body></html>"""
    resp.set_data(html)
    return resp


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
            </body></html>'''
        resp.set_data(html)
        return resp

    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'user' and password == 'pass':
        sid = request.cookies.get('sessionid') or str(uuid.uuid4())
        SESSIONS[sid] = username
        issue_header_token(sid)
        issue_per_request_token(sid)
        resp = make_response(redirect('/'))
        resp.set_cookie('sessionid', sid, httponly=True, samesite='Lax')
        return resp

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


# -----------------------
# Vulnerable endpoints (demonstration)
# -----------------------
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
    return "OK - no token required", 200


@app.route("/vuln/static_token", methods=["GET", "POST"])
def vuln_static_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = f"""<html><body>
        <h3>Vuln: static token</h3>
        <form method="POST" action="/vuln/static_token">
            <input type="hidden" name="csrf_token" value="{STATIC_TOKEN}"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        return resp
    return "OK - static token ignored", 200


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
        set_csrf_cookie_only(resp)
        resp.set_data(html)
        return resp
    return "OK - cookie only", 200


@app.route("/vuln/action_with_token_in_get", methods=["GET"])
def vuln_token_in_get():
    sid, resp = ensure_session()
    html = f"""<html><body>
    <h3>Vuln: token in GET</h3>
    <form method="GET" action="/vuln/do_get_action?csrf_token={STATIC_TOKEN}">
        <button type="submit">Do GET Action</button>
    </form>
    </body></html>"""
    resp.set_data(html)
    return resp


@app.route("/vuln/do_get_action", methods=["GET"])
def vuln_do_get_action():
    return "OK - GET changed state", 200


# -----------------------
# Secure endpoints
# -----------------------
@app.route("/secure/per_request_token", methods=["GET", "POST"])
def secure_per_request_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_per_request_token(sid)
        html = f"""<html><body>
        <h3>Secure: per request token</h3>
        <form method="POST" action="/secure/per_request_token">
            <input type="hidden" name="csrf_token" value="{token}"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        return resp

    form_token = request.form.get("csrf_token")
    expected = SESSION_TOKENS.get(sid)
    if form_token and expected and form_token == expected:
        SESSION_TOKENS[sid] = str(uuid.uuid4())  # rotate
        return "OK - valid token", 200
    return "Forbidden - invalid/missing token", 403


@app.route("/secure/token_in_header", methods=["GET", "POST"])
def secure_token_in_header():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_header_token(sid)
        html = f"""<html><head>
        <meta name="csrf-token" content="{token}"/>
        </head><body>
        <h3>Secure: token in header</h3>
        <form method="POST" action="/secure/token_in_header">
            <input type="hidden" name="foo" value="bar"/>
            <p>Client must send X-CSRF-Token header with this value.</p>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        return resp

    hdr = request.headers.get("X-CSRF-Token")
    expected = SESSION_HEADER_TOKENS.get(sid)
    if hdr and expected and hdr == expected:
        SESSION_HEADER_TOKENS[sid] = str(uuid.uuid4())  # rotate
        return "OK - header token", 200
    return "Forbidden - missing/invalid header token", 403


# -----------------------
# Edge case (vulnerable)
# -----------------------
@app.route("/edge/token_same_across_sessions", methods=["GET", "POST"])
def edge_same_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = f"""<html><body>
        <h3>Edge: same token across sessions</h3>
        <form method="POST" action="/edge/token_same_across_sessions">
            <input type="hidden" name="csrf_token" value="{STATIC_TOKEN}"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>"""
        resp.set_data(html)
        return resp
    return "OK - not tied to session", 200


# -----------------------
# POSITIVE TESTS (vulnerable)
# -----------------------
@app.route("/pos/no_token_post", methods=["GET", "POST"])
def pos_no_token_post():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Pos Test: no token in POST</h3>
        <form method="POST" action="/pos/no_token_post">
            <input type="text" name="data" value="example"/>
            <button type="submit">Submit</button>
        </form>
        <p>No CSRF token used — should be flagged as vulnerable.</p>
        </body></html>"""
        resp.set_data(html)
        return resp
    return "OK - accepted without CSRF token (positive test)", 200


@app.route("/pos/static_token", methods=["GET", "POST"])
def pos_static_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = f"""<html><body>
        <h3>Pos Test: static token reused</h3>
        <form method="POST" action="/pos/static_token">
            <input type="hidden" name="csrf_token" value="{STATIC_TOKEN}"/>
            <button type="submit">Submit</button>
        </form>
        <p>Same token across all sessions — should be flagged as vulnerable.</p>
        </body></html>"""
        resp.set_data(html)
        return resp
    return "OK - accepted static token (positive test)", 200


@app.route("/pos/token_in_get", methods=["GET"])
def pos_token_in_get():
    sid, resp = ensure_session()
    html = f"""<html><body>
    <h3>Pos Test: token in GET</h3>
    <form method="GET" action="/pos/do_get_action?csrf_token={STATIC_TOKEN}">
        <button type="submit">Submit GET Action</button>
    </form>
    <p>CSRF token is visible in query string — should be flagged as vulnerable.</p>
    </body></html>"""
    resp.set_data(html)
    return resp


@app.route("/pos/do_get_action", methods=["GET"])
def pos_do_get_action():
    return "OK - GET action performed (positive test)", 200


# -----------------------
# NEGATIVE TESTS (secure)
# -----------------------
@app.route("/neg/token_present", methods=["GET", "POST"])
def neg_token_present():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_per_request_token(sid)
        html = f"""<html><body>
        <h3>Neg Test: token present & rotating</h3>
        <form method="POST" action="/neg/token_present">
            <input type="hidden" name="csrf_token" value="{token}"/>
            <button type="submit">Submit</button>
        </form>
        <p>This endpoint issues a fresh token per GET and rotates on success.</p>
        </body></html>"""
        resp.set_data(html)
        return resp

    form_token = request.form.get("csrf_token")
    expected = SESSION_TOKENS.get(sid)
    if form_token and expected and form_token == expected:
        SESSION_TOKENS[sid] = str(uuid.uuid4())
        return "OK - valid rotating token (negative test)", 200
    return "Forbidden - invalid/missing token", 403


@app.route("/neg/token_nonce", methods=["GET", "POST"])
def neg_token_nonce():
    sid, resp = ensure_session()
    if request.method == "GET":
        nonce = issue_nonce(sid)
        html = f"""<html><body>
        <h3>Neg Test: single-use nonce</h3>
        <form method="POST" action="/neg/token_nonce">
            <input type="hidden" name="csrf_nonce" value="{nonce}"/>
            <button type="submit">Submit</button>
        </form>
        <p>This endpoint issues a unique nonce each GET; once POSTed, the nonce is consumed.</p>
        </body></html>"""
        resp.set_data(html)
        return resp

    form_nonce = request.form.get("csrf_nonce")
    if form_nonce and consume_nonce(sid, form_nonce):
        return "OK - valid single-use nonce (negative test)", 200
    return "Forbidden - invalid/missing/used nonce", 403


# -----------------------
# Main entry
# -----------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
