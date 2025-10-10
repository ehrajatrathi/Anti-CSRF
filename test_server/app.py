# Flask test server to demonstrate CSRF detections
# IMPORTANT: Defensive/testing use only. Do not expose publicly.
from flask import Flask, request, make_response, jsonify, redirect
import os
import uuid
import time

app = Flask(__name__)
app.secret_key = "dev-secret"

# In-memory stores for demo; do NOT use in production
STATIC_TOKEN = "STATIC-TOKEN-12345"
SESSION_TOKENS = {}          # session_id -> token
SESSION_HEADER_TOKENS = {}   # session_id -> header token

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

@app.route("/")
def index():
    return """<html><body>
    <h3>CSRF test server</h3>
    <ul>
      <li><a href="/vuln/no_token">/vuln/no_token</a></li>
      <li><a href="/vuln/static_token">/vuln/static_token</a></li>
      <li><a href="/vuln/cookie_only">/vuln/cookie_only</a></li>
      <li><a href="/vuln/action_with_token_in_get">/vuln/action_with_token_in_get</a></li>
      <li><a href="/secure/per_request_token">/secure/per_request_token</a></li>
      <li><a href="/secure/token_in_header">/secure/token_in_header</a></li>
      <li><a href="/edge/token_same_across_sessions">/edge/token_same_across_sessions</a></li>
    </ul>
    </body></html>""", 200

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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)


