# app.py
# Test server with CSRF endpoints + JS-vulnerability demo pages.
# Defensive/testing use only. Do not expose publicly.

from flask import Flask, request, make_response, jsonify, redirect, send_from_directory
import os
import uuid

app = Flask(__name__, static_folder="static")
app.secret_key = "dev-secret"

STATIC_TOKEN = "STATIC-TOKEN-12345"
SESSION_TOKENS = {}
SESSION_HEADER_TOKENS = {}
SESSIONS = {}

def ensure_session():
    sid = request.cookies.get("sessionid")
    if not sid:
        sid = str(uuid.uuid4())
    resp = make_response()
    resp.set_cookie("sessionid", sid, httponly=True, samesite="Lax")
    return sid, resp

def set_csrf_cookie_only(resp):
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

@app.route("/")
def index():
    sid, resp = ensure_session()
    user = SESSIONS.get(sid)
    username_html = f"<p>Logged in as: <strong>{user}</strong></p>" if user else "<p>Not logged in</p>"
    html = f"""<html><body>
    <h3>CSRF & JS test server</h3>
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
      <li><strong>JS tests</strong></li>
      <li><a href="/js/cross_domain_no_sri">/js/cross_domain_no_sri</a></li>
      <li><a href="/js/cross_domain_with_sri">/js/cross_domain_with_sri</a></li>
      <li><a href="/js/protocol_relative">/js/protocol_relative</a></li>
      <li><a href="/js/inline_eval">/js/inline_eval</a></li>
      <li><a href="/js/onclick_handler">/js/onclick_handler</a></li>
      <li><a href="/logout">/logout</a></li>
    </ul>
    </body></html>"""
    resp.set_data(html)
    return resp

# --- (existing auth/logout/login and CSRF endpoints) ---
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
        sid = request.cookies.get('sessionid')
        if not sid:
            sid = str(uuid.uuid4())
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
    resp = make_response(redirect('/'))
    resp.set_cookie('sessionid', '', expires=0)
    return resp

# CSRF endpoints (unchanged)
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
        html = """<html><body>
        <h3>Vuln: static token</h3>
        <form method="POST" action="/vuln/static_token">
            <input type="hidden" name="csrf_token" value="%s"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % STATIC_TOKEN
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
        resp.set_data(html)
        set_csrf_cookie_only(resp)
        return resp
    return "OK - cookie only", 200

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
    return "OK - GET changed state", 200

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
    form_token = request.form.get("csrf_token")
    expected = SESSION_TOKENS.get(sid)
    if form_token and expected and form_token == expected:
        SESSION_TOKENS[sid] = str(uuid.uuid4())
        return "OK - valid token", 200
    return "Forbidden - invalid/missing token", 403

@app.route("/secure/token_in_header", methods=["GET", "POST"])
def secure_token_in_header():
    sid, resp = ensure_session()
    if request.method == "GET":
        token = issue_header_token(sid)
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
    hdr = request.headers.get("X-CSRF-Token")
    expected = SESSION_HEADER_TOKENS.get(sid)
    if hdr and expected and hdr == expected:
        SESSION_HEADER_TOKENS[sid] = str(uuid.uuid4())
        return "OK - header token", 200
    return "Forbidden - missing/invalid header token", 403

@app.route("/edge/token_same_across_sessions", methods=["GET", "POST"])
def edge_same_token():
    sid, resp = ensure_session()
    if request.method == "GET":
        html = """<html><body>
        <h3>Edge: same token across sessions</h3>
        <form method="POST" action="/edge/token_same_across_sessions">
            <input type="hidden" name="csrf_token" value="%s"/>
            <button type="submit">Submit</button>
        </form>
        </body></html>""" % STATIC_TOKEN
        resp.set_data(html)
        return resp
    return "OK - not tied to session", 200

# --- JS vulnerability demo pages ---
# Assume a separate "cdn" host runs on http://127.0.0.1:5001 serving /cdn/evil.js

@app.route("/js/cross_domain_no_sri")
def js_cross_domain_no_sri():
    # absolute cross-domain include (different port => different netloc)
    html = """<html><body>
    <h3>Cross-domain script (no SRI)</h3>
    <p>This page loads a script from http://127.0.0.1:5001/cdn/evil.js (no integrity attribute).</p>
    <script src="http://127.0.0.1:5001/cdn/evil.js"></script>
    </body></html>"""
    return html

@app.route("/js/cross_domain_with_sri")
def js_cross_domain_with_sri():
    # include with integrity (example hash is fake, purpose is to show presence)
    html = """<html><body>
    <h3>Cross-domain script (with SRI)</h3>
    <p>This page loads a script from http://127.0.0.1:5001/cdn/evil.js with integrity attr.</p>
    <script src="http://127.0.0.1:5001/cdn/evil.js" integrity="sha384-FAKEHASH" crossorigin="anonymous"></script>
    </body></html>"""
    return html

@app.route("/js/protocol_relative")
def js_protocol_relative():
    # protocol-relative url: //127.0.0.1:5001/cdn/evil.js
    html = """<html><body>
    <h3>Protocol-relative script include</h3>
    <p>Protocol-relative includes should be treated as absolute for host checks.</p>
    <script src="//127.0.0.1:5001/cdn/evil.js"></script>
    </body></html>"""
    return html

@app.route("/js/inline_eval")
def js_inline_eval():
    # inline script that uses eval and document.write and innerHTML
    html = """<html><body>
    <h3>Inline dangerous JS</h3>
    <script>
      // intentionally dangerous for testing
      var userCode = "alert('xss')";
      eval(userCode);
      document.getElementById = function(){}; // harmless filler
      document.write("<div>document.write used</div>");
      var el = document.createElement('div');
      el.innerHTML = "<span>bad innerHTML</span>";
      console.log("done");
    </script>
    </body></html>"""
    return html

@app.route("/js/onclick_handler")
def js_onclick_handler():
    html = """<html><body>
    <h3>Inline event handler</h3>
    <button onclick="eval('console.log(\\'clicked\\')')">Click me</button>
    </body></html>"""
    return html

# static files if you want to serve other assets
@app.route("/static/<path:filename>")
def static_files(filename):
    # serve from ./static directory
    return send_from_directory(os.path.join(os.getcwd(), "static"), filename)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=True)
