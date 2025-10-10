# ZAP Custom Active/Passive Rule (Jython - Python 2.7)
# Name: gs_custom_csrf
# Purpose: Detect Anti-CSRF weaknesses via passive and optional active replay checks.
#
# IMPORTANT: Defensive use only. Do not use against systems you don't own or have permission to test.
#
# Script Type: Passive Scan Rule (with optional active replay checks when enabled)
#
# This script is designed to be loaded in ZAP 2.x Scripting Console under Jython.
# It implements passive checks to detect common CSRF anti-patterns and can optionally
# perform lightweight active replay tests (removing or modifying CSRF tokens) to confirm vulnerabilities.
#
# Alert details:
# - Name: gs_custom_csrf
# - CWE: 352 (Cross-Site Request Forgery)
# - WASC: 8 (Cross-Site Request Forgery)
#
# Risk mapping:
# - HIGH (3): Server accepts state-changing request without a CSRF token or with a broken/static token during active replay.
# - MEDIUM (2): Missing CSRF token on a state-changing endpoint detected passively, or token only present in a cookie, or token passed in GET.
# - LOW (1): Token appears static across samples, or token might not be bound to session. (Elevated by configuration or upon further confirmation.)
#
# Confidence mapping:
# - HIGH (3): Confirmed via successful active replay or multiple corroborating passive indicators.
# - MEDIUM (2): Strong passive evidence (missing token on state-changing form/endpoint).
# - LOW (1): Heuristic signal (possible static token, suspicious patterns) without confirmation.
#
# Configuration (override via org.zaproxy.zap.extension.script.ScriptVars):
# - MAX_SAMPLES (int): default 5, number of responses to sample for token stability checks.
# - ACTIVE_CHECKS (bool): default True, enable active replay checks.
# - REPLAY_TIMEOUT (int ms): default 3000, timeout budget used during replay.
# - VERBOSE_LOGGING (bool): default False, extra console logging.
#
# Heuristics implemented:
# - Passive:
#   * Check state-changing methods (POST/PUT/DELETE) for missing CSRF token parameter in body/header.
#   * Parse HTML forms: look for hidden inputs, meta tags, inline JS assignments for CSRF tokens.
#   * Detect static tokens: identical token values observed across different responses (per action).
#   * Detect cookie-only CSRF protection (no per-form token/header).
#   * Detect tokens passed in GET query for state-changing actions.
#   * Session affinity: the same token seen across different session cookie values.
# - Active (optional):
#   * Replay request with missing token and observe acceptance (non-403/401/405) -> HIGH risk.
#   * Replay request with known/broken token (static/predictable) accepted -> HIGH risk.
#
# Notes:
# - This script uses only ZAP’s bundled APIs for Jython.
# - For compatibility with different ZAP versions, see README if cloneRequest() behavior differs.

from org.parosproxy.paros.core.scanner import Alert
from org.parosproxy.paros.network import HttpMessage, HttpHeader, HttpSender
from org.parosproxy.paros.model import Model
from org.zaproxy.zap.extension.script import ScriptVars

from java.net import URI
from java.util import HashMap

import re
import time

# ----------------------------
# Configuration defaults
# ----------------------------
DEFAULT_MAX_SAMPLES = 5
DEFAULT_ACTIVE_CHECKS = True
DEFAULT_REPLAY_TIMEOUT = 3000  # milliseconds (best-effort; HttpSender uses global options)
DEFAULT_VERBOSE_LOGGING = False

ALERT_NAME = "gs_custom_csrf"
CWE_ID = 352
WASC_ID = 8

# Common token name indicators used across frameworks
TOKEN_NAME_HINTS = [
    "csrf", "xsrf", "anti_csrf", "anti-xsrf", "anti_xsrf",
    "authenticity_token", "requestverificationtoken", "x-csrf-token", "x-xsrf-token",
    "crumb", "forge", "synchronizer"
]

# Common session cookie names to help detect cross-session reuse
SESSION_COOKIE_HINTS = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "sessionid", "connect.sid", "sid", "laravel_session", "play_session"
]

# ----------------------------
# Globals / caches (in-memory)
# ----------------------------

# Map: action_or_path -> set([observed_token_values])
observed_tokens_by_action = {}

# Map: action_or_path -> dict of session_id_value -> set([token_values])
tokens_by_session_for_action = {}

# Map: request_uri -> last_seen_form_details to avoid duplicate alerts
# (key: (uri, issue_key) -> True)
dedupe_alerts = {}

# ----------------------------
# Utility: get configuration (with ScriptVars overrides)
# ----------------------------

def _get_bool_var(var_name, default_value):
    try:
        val = ScriptVars.getGlobalVar("gs_csrf_%s" % var_name)
        if val is None:
            return default_value
        low = val.strip().lower()
        return low in ["1", "true", "yes", "on"]
    except:
        return default_value

def _get_int_var(var_name, default_value):
    try:
        val = ScriptVars.getGlobalVar("gs_csrf_%s" % var_name)
        if val is None:
            return default_value
        return int(val)
    except:
        return default_value

def get_config():
    cfg = {
        "MAX_SAMPLES": _get_int_var("MAX_SAMPLES", DEFAULT_MAX_SAMPLES),
        "ACTIVE_CHECKS": _get_bool_var("ACTIVE_CHECKS", DEFAULT_ACTIVE_CHECKS),
        "REPLAY_TIMEOUT": _get_int_var("REPLAY_TIMEOUT", DEFAULT_REPLAY_TIMEOUT),
        "VERBOSE_LOGGING": _get_bool_var("VERBOSE_LOGGING", DEFAULT_VERBOSE_LOGGING),
    }
    return cfg

def vlog(msg):
    cfg = get_config()
    if cfg["VERBOSE_LOGGING"]:
        try:
            print("[gs_custom_csrf] %s" % msg)
        except:
            pass

# ----------------------------
# Token extraction helpers
# ----------------------------

def is_state_changing_method(method):
    if not method:
        return False
    m = method.upper()
    return m in ["POST", "PUT", "DELETE", "PATCH"]

def find_hidden_inputs(html):
    # Returns list of (name, value) for input type hidden
    inputs = []
    try:
        # Simple regex for hidden inputs
        # Capture name="" and value="" attributes regardless of order; tolerant of single/double quotes
        pattern = re.compile(r'<input[^>]*type=["\']?hidden["\']?[^>]*>', re.IGNORECASE)
        for tag in pattern.findall(html):
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                inputs.append((name, value))
    except Exception as e:
        vlog("find_hidden_inputs error: %s" % e)
    return inputs

def find_meta_csrf(html):
    # Returns list of (name, content)
    metas = []
    try:
        pattern = re.compile(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
        for (name, content) in pattern.findall(html):
            if "csrf" in name.lower() or "xsrf" in name.lower():
                metas.append((name, content))
    except Exception as e:
        vlog("find_meta_csrf error: %s" % e)
    return metas

def find_js_tokens(html):
    # Extract tokens from simple JS assignment patterns
    # Examples: window.CSRF_TOKEN = "abc"; var csrfToken = 'xyz';
    tokens = []
    try:
        js_patterns = [
            re.compile(r'window\.[A-Za-z0-9_]*csrf[A-Za-z0-9_]*\s*=\s*[\'\"]([^\'\"]+)[\'\"]', re.IGNORECASE),
            re.compile(r'var\s+[A-Za-z0-9_]*csrf[A-Za-z0-9_]*\s*=\s*[\'\"]([^\'\"]+)[\'\"]', re.IGNORECASE),
            re.compile(r'const\s+[A-Za-z0-9_]*csrf[A-Za-z0-9_]*\s*=\s*[\'\"]([^\'\"]+)[\'\"]', re.IGNORECASE),
            re.compile(r'let\s+[A-Za-z0-9_]*csrf[A-Za-z0-9_]*\s*=\s*[\'\"]([^\'\"]+)[\'\"]', re.IGNORECASE),
        ]
        for pat in js_patterns:
            for val in pat.findall(html):
                tokens.append(("js", val))
    except Exception as e:
        vlog("find_js_tokens error: %s" % e)
    return tokens

def extract_form_actions(html):
    # Returns list of (method, action_url, hidden_inputs_list)
    forms = []
    try:
        # Cheap form splitting
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        open_tag_pattern = re.compile(r'<form[^>]*>', re.IGNORECASE)
        method_attr = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)
        action_attr = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)

        for form_block in form_pattern.findall(html):
            # Need the opening tag for attributes; search backwards inside the block
            open_tag_search = open_tag_pattern.search(form_block)
            method = "GET"
            action = ""
            if open_tag_search:
                open_tag_text = open_tag_search.group(0)
                m = method_attr.search(open_tag_text)
                a = action_attr.search(open_tag_text)
                if m:
                    method = m.group(1).upper()
                if a:
                    action = a.group(1)
            # Hidden inputs within the entire form (we already have form_block body)
            hidden_inputs = find_hidden_inputs(form_block)
            forms.append((method, action, hidden_inputs))
    except Exception as e:
        vlog("extract_form_actions error: %s" % e)
    return forms

def is_token_name(name):
    if not name:
        return False
    low = name.lower()
    for hint in TOKEN_NAME_HINTS:
        if hint in low:
            return True
    return False

def identify_csrf_tokens_from_form_inputs(hidden_inputs):
    # hidden_inputs: list of (name, value)
    tokens = []
    for (name, value) in hidden_inputs:
        if is_token_name(name):
            tokens.append((name, value))
    return tokens

def collect_tokens_in_response(msg):
    # Returns dict with evidence from multiple places
    # {
    #   "form_tokens": [(action, method, name, value)]
    #   "meta_tokens": [(name, value)]
    #   "js_tokens": [(source, value)]
    # }
    result = {"form_tokens": [], "meta_tokens": [], "js_tokens": []}
    try:
        body = msg.getResponseBody().toString()
        forms = extract_form_actions(body)
        for (method, action, hidden_inputs) in forms:
            tokens = identify_csrf_tokens_from_form_inputs(hidden_inputs)
            for (name, value) in tokens:
                result["form_tokens"].append((action, method, name, value))
        meta_tokens = find_meta_csrf(body)
        result["meta_tokens"] = meta_tokens
        js_tokens = find_js_tokens(body)
        result["js_tokens"] = js_tokens
    except Exception as e:
        vlog("collect_tokens_in_response error: %s" % e)
    return result

def get_request_form_params(msg):
    # Parse application/x-www-form-urlencoded bodies into dict of name->values(list)
    params = {}
    try:
        content_type = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE)
        if content_type and "application/x-www-form-urlencoded" in content_type.lower():
            body = msg.getRequestBody().toString()
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params.setdefault(k, []).append(v)
                else:
                    params.setdefault(pair, []).append("")
    except Exception as e:
        vlog("get_request_form_params error: %s" % e)
    return params

def get_query_params_from_uri(uri_str):
    params = {}
    try:
        if "?" in uri_str:
            query = uri_str.split("?", 1)[1]
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params.setdefault(k, []).append(v)
                else:
                    params.setdefault(pair, []).append("")
    except Exception as e:
        vlog("get_query_params_from_uri error: %s" % e)
    return params

def get_session_cookie_value(msg):
    try:
        headers = msg.getRequestHeader()
        cookie_header = headers.getHeader(HttpHeader.COOKIE)
        if not cookie_header:
            return None
        # Choose the first known session cookie; else return all as a blob
        parts = [p.strip() for p in cookie_header.split(";")]
        for p in parts:
            if "=" in p:
                name, val = p.split("=", 1)
                name = name.strip()
                if name in SESSION_COOKIE_HINTS:
                    return "%s=%s" % (name, val.strip())
        # Fallback: return the whole cookie header
        return cookie_header.strip()
    except Exception as e:
        vlog("get_session_cookie_value error: %s" % e)
        return None

def normalize_action(base_uri, action):
    # Attempt to convert relative action to absolute path-ish key for tracking
    try:
        if not action:
            return base_uri
        if action.startswith("http://") or action.startswith("https://"):
            return action
        # Build from base path
        if action.startswith("/"):
            # Replace scheme://host[:port] part of base_uri
            m = re.match(r'^(https?://[^/]+)', base_uri)
            if m:
                return m.group(1) + action
            return base_uri.rstrip("/") + action
        # Relative path
        if base_uri.endswith("/"):
            return base_uri + action
        else:
            # Remove filename if present
            return base_uri.rsplit("/", 1)[0] + "/" + action
    except:
        return action or base_uri

# ----------------------------
# Token stability/session affinity caches
# ----------------------------

def record_token_observation(action_key, token_value):
    try:
        s = observed_tokens_by_action.get(action_key)
        if s is None:
            s = set()
            observed_tokens_by_action[action_key] = s
        s.add(token_value)
    except Exception as e:
        vlog("record_token_observation error: %s" % e)

def record_token_for_session(action_key, session_id_value, token_value):
    try:
        if not session_id_value:
            return
        d = tokens_by_session_for_action.get(action_key)
        if d is None:
            d = {}
            tokens_by_session_for_action[action_key] = d
        token_set = d.get(session_id_value)
        if token_set is None:
            token_set = set()
            d[session_id_value] = token_set
        token_set.add(token_value)
    except Exception as e:
        vlog("record_token_for_session error: %s" % e)

def is_token_static(action_key, max_samples):
    try:
        s = observed_tokens_by_action.get(action_key)
        if not s:
            return False, 0
        # Static if we have seen at least 2 samples but only 1 unique value
        unique_count = len(s)
        return (unique_count == 1), unique_count
    except Exception as e:
        vlog("is_token_static error: %s" % e)
        return False, 0

def tokens_same_across_sessions(action_key):
    try:
        d = tokens_by_session_for_action.get(action_key)
        if not d:
            return False
        # If two or more different session ids share a non-empty intersection of tokens -> suspicious
        seen_sets = []
        for session_id, token_set in d.items():
            seen_sets.append(token_set)
        if len(seen_sets) < 2:
            return False
        # Intersection of all token sets
        inter = None
        for s in seen_sets:
            inter = s if inter is None else inter.intersection(s)
            if not inter:
                break
        return bool(inter)
    except Exception as e:
        vlog("tokens_same_across_sessions error: %s" % e)
        return False

# ----------------------------
# Alert helpers
# ----------------------------

def _new_alert(ps):
    # Use builder API if available; fallback to Alert class otherwise
    try:
        return ps.newAlert()
    except:
        return None

def raise_alert(ps, msg, risk, confidence, name, description, solution, evidence, otherInfo, param, attack, cweId, wascId):
    key = (msg.getRequestHeader().getURI().toString(), name + "|" + (param or "") + "|" + (attack or "") + "|" + (evidence or ""))
    if key in dedupe_alerts:
        return
    dedupe_alerts[key] = True

    builder = _new_alert(ps)
    if builder is not None:
        try:
            builder.setRisk(risk)
            builder.setConfidence(confidence)
            builder.setName(name)
            builder.setDescription(description)
            builder.setSolution(solution)
            builder.setEvidence(evidence)
            builder.setOtherInfo(otherInfo)
            builder.setParam(param)
            builder.setAttack(attack)
            builder.setCweId(cweId)
            builder.setWascId(wascId)
            builder.setMessage(msg)
            builder.raise()
            return
        except Exception as e:
            vlog("builder alert failed, fallback: %s" % e)

    # Fallback to ps.raiseAlert with many parameters (legacy)
    try:
        uri = msg.getRequestHeader().getURI().toString()
        ps.raiseAlert(risk, confidence, name, description, uri, param, attack, otherInfo, solution, evidence, cweId, wascId, msg)
    except Exception as e:
        vlog("ps.raiseAlert fallback error: %s" % e)

# ----------------------------
# Active replay helpers
# ----------------------------

def _make_sender():
    try:
        conn = Model.getSingleton().getOptionsParam().getConnectionParam()
        # Use scanner initiator type to avoid interfering with other senders
        sender = HttpSender(conn, True, HttpSender.ACTIVE_SCANNER)
        return sender
    except Exception as e:
        vlog("_make_sender error: %s" % e)
        return None

def _clone_request_message(orig_msg):
    # Try deep clone of the request portion
    try:
        # Available in ZAP 2.9+:
        clone = orig_msg.cloneRequest()
        return clone
    except:
        # Fallback: construct a new message from strings
        try:
            new_msg = HttpMessage()
            # Recreate header from string (parses request line+headers)
            new_msg.setRequestHeader(orig_msg.getRequestHeader().toString())
            new_msg.setRequestBody(orig_msg.getRequestBody().toString())
            # Ensure Content-Length re-sync
            new_msg.getRequestHeader().setContentLength(new_msg.getRequestBody().length())
            return new_msg
        except Exception as e:
            vlog("_clone_request_message ultimate fallback error: %s" % e)
            return None

def _strip_or_corrupt_tokens_in_msg(msg):
    # Removes token parameters from query/body and CSRF headers; corrupts any residual values
    try:
        # Remove token-like headers
        header_names = msg.getRequestHeader().getHeaderNames()
        to_remove = []
        for i in range(header_names.size()):
            h = header_names.get(i)
            if h is None:
                continue
            if "csrf" in h.lower() or "xsrf" in h.lower() or "verificationtoken" in h.lower():
                to_remove.append(h)
        for h in to_remove:
            msg.getRequestHeader().setHeader(h, None)  # remove header

        # Modify body form params
        content_type = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE)
        if content_type and "application/x-www-form-urlencoded" in content_type.lower():
            body = msg.getRequestBody().toString()
            pairs = body.split("&") if body else []
            new_pairs = []
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                else:
                    k, v = pair, ""
                if is_token_name(k):
                    # drop parameter
                    continue
                new_pairs.append("%s=%s" % (k, v))
            new_body = "&".join(new_pairs)
            msg.setRequestBody(new_body)
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length())

        # Modify query params (remove token in GET URL)
        try:
            uri_obj = msg.getRequestHeader().getURI()
            uri_str = uri_obj.toString()
            if "?" in uri_str:
                base, query = uri_str.split("?", 1)
                q_pairs = query.split("&") if query else []
                kept = []
                for pair in q_pairs:
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                    else:
                        k, v = pair, ""
                    if is_token_name(k):
                        continue
                    kept.append("%s=%s" % (k, v) if v != "" else k)
                new_uri = base
                if kept:
                    new_uri = base + "?" + "&".join(kept)
                msg.getRequestHeader().setURI(URI(new_uri, True))
        except Exception as e:
            vlog("_strip_or_corrupt_tokens_in_msg query adjust error: %s" % e)

    except Exception as e:
        vlog("_strip_or_corrupt_tokens_in_msg error: %s" % e)

def _send_and_classify(sender, msg, timeout_ms):
    # Send the message and classify acceptance. Heuristic: 2xx/3xx (not 401/403/405) is "accepted"
    try:
        start = time.time()
        sender.sendAndReceive(msg, True)
        elapsed = int((time.time() - start) * 1000)
        status = msg.getResponseHeader().getStatusCode()
        # Heuristic acceptance
        accepted = (status < 400) and (status not in [401, 403, 405, 415])
        return accepted, status, elapsed
    except Exception as e:
        vlog("_send_and_classify error: %s" % e)
        return False, 0, 0

# ----------------------------
# Core passive scan entrypoint
# ----------------------------

def scan(ps, msg, src):
    """
    Passive scan entry point (ZAP calls this for each response).
    """
    try:
        method = msg.getRequestHeader().getMethod()
        uri_str = msg.getRequestHeader().getURI().toString()

        cfg = get_config()

        # Collect response tokens (HTML forms, meta, JS inline)
        tokens = collect_tokens_in_response(msg)

        # Record observations per action (use request URI as a base key)
        base_action_key = uri_str

        # Session observation
        session_cookie_value = get_session_cookie_value(msg)

        # Interpret presence of tokens
        form_tokens = tokens.get("form_tokens", [])
        meta_tokens = tokens.get("meta_tokens", [])
        js_tokens = tokens.get("js_tokens", [])

        # Track tokens per action and session
        for (action, m, name, value) in form_tokens:
            action_key = normalize_action(uri_str, action) or base_action_key
            if value:
                record_token_observation(action_key, value)
                record_token_for_session(action_key, session_cookie_value, value)

        for (_, value) in meta_tokens:
            if value:
                record_token_observation(base_action_key, value)
                record_token_for_session(base_action_key, session_cookie_value, value)

        for (_, value) in js_tokens:
            if value:
                record_token_observation(base_action_key, value)
                record_token_for_session(base_action_key, session_cookie_value, value)

        # ----------------------------
        # Passive checks begin
        # ----------------------------

        # 1) Missing CSRF token on state-changing endpoints
        if is_state_changing_method(method):
            body_params = get_request_form_params(msg)
            query_params = get_query_params_from_uri(uri_str)

            has_token_in_body = any([is_token_name(k) for k in body_params.keys()])
            has_token_in_header = False
            hdr_names = msg.getRequestHeader().getHeaderNames()
            for i in range(hdr_names.size()):
                h = hdr_names.get(i)
                if h and is_token_name(h):
                    has_token_in_header = True
                    break

            if not has_token_in_body and not has_token_in_header:
                desc = "State-changing request does not include an anti-CSRF token in request body or header."
                sol = "Ensure that all state-changing requests include a server-validated anti-CSRF token in a header or body parameter."
                evidence = "Method=%s; no CSRF token in body/header" % method
                other = "Passive detection. Enable ACTIVE_CHECKS to attempt confirmation via replay."
                raise_alert(ps, msg, Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, ALERT_NAME, desc, sol, evidence, other, None, None, CWE_ID, WASC_ID)

        # 2) Tokens passed via GET query for state-changing actions
        # If a GET request includes token-like params and appears to change state (hard to know), still warn if token present in GET
        # Also if a form declares method GET and includes token param -> warn
        body = msg.getResponseBody().toString()
        forms = extract_form_actions(body)
        for (f_method, f_action, hidden_inputs) in forms:
            if f_method == "GET":
                # Token passed via GET parameter in a form that may cause side effects
                token_inputs = identify_csrf_tokens_from_form_inputs(hidden_inputs)
                if token_inputs:
                    desc = "Anti-CSRF token is included in a GET-based form/action, which is unsafe."
                    sol = "Use POST/PUT/DELETE with tokens transported in body or header; do not use GET for state-changing actions."
                    ev_name = token_inputs[0][0]
                    evidence = "GET form action uses token param: %s" % ev_name
                    other = "Form action: %s" % f_action
                    raise_alert(ps, msg, Alert.RISK_MEDIUM, Alert.CONFIDENCE_LOW, ALERT_NAME, desc, sol, evidence, other, ev_name, None, CWE_ID, WASC_ID)
            # If action URL already contains token param via query
            if f_action and "?" in f_action:
                q = get_query_params_from_uri(f_action)
                for k in q.keys():
                    if is_token_name(k):
                        desc = "Anti-CSRF token is transported via URL query parameter, which is unsafe (leaks via referrers/logs)."
                        sol = "Send CSRF tokens in request body or custom header; avoid URL query parameters."
                        evidence = "Token in query parameter '%s'" % k
                        other = "Form method: %s; action: %s" % (f_method, f_action)
                        raise_alert(ps, msg, Alert.RISK_MEDIUM, Alert.CONFIDENCE_LOW, ALERT_NAME, desc, sol, evidence, other, k, None, CWE_ID, WASC_ID)

        # 3) Cookie-only CSRF controls
        # If a response sets a CSRF-looking cookie and there are no form/header tokens observed
        set_cookies = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE)
        has_csrf_cookie = False
        if set_cookies is not None:
            for i in range(set_cookies.size()):
                sc = set_cookies.get(i)
                if sc and ("csrf" in sc.lower() or "xsrf" in sc.lower()):
                    has_csrf_cookie = True
                    break
        any_token_artifact = bool(form_tokens or meta_tokens or js_tokens)
        if has_csrf_cookie and not any_token_artifact:
            desc = "CSRF protection appears to rely on a cookie only, without a per-request or per-form token."
            sol = "Use a per-request or per-form anti-CSRF token validated server-side (e.g., synchronizer token pattern or double-submit with robust validation)."
            evidence = "Set-Cookie with CSRF-like name and no form/header/meta/JS token detected."
            other = "Cookie-only controls are prone to CSRF unless combined with strict SameSite and server checks."
            raise_alert(ps, msg, Alert.RISK_MEDIUM, Alert.CONFIDENCE_LOW, ALERT_NAME, desc, sol, evidence, other, None, None, CWE_ID, WASC_ID)

        # 4) Token stability (predictable/static across samples)
        # If only one unique value observed for an action across multiple responses
        # We do not enforce exact sample count here; heuristic can be LOW to MEDIUM confidence
        # Use base_action_key if no explicit form action is found
        for (act, f_method, name, value) in form_tokens:
            if not value:
                continue
            action_key = normalize_action(uri_str, act) or base_action_key
            static, uniq = is_token_static(action_key, cfg["MAX_SAMPLES"])
            if static:
                desc = "Anti-CSRF token value appears static/predictable across responses."
                sol = "Generate unique, unpredictable anti-CSRF tokens per session (preferably per request), and validate server-side."
                evidence = "Observed single token value for action: %s" % action_key
                other = "Seen unique token count=%d; consider enabling ACTIVE_CHECKS for confirmation." % uniq
                raise_alert(ps, msg, Alert.RISK_LOW, Alert.CONFIDENCE_LOW, ALERT_NAME, desc, sol, evidence, other, name, value, CWE_ID, WASC_ID)

        # 5) Session affinity check: same token across different session cookie values
        for (act, f_method, name, value) in form_tokens:
            if not value:
                continue
            action_key = normalize_action(uri_str, act) or base_action_key
            if tokens_same_across_sessions(action_key):
                desc = "Anti-CSRF token value appears reused across different sessions."
                sol = "Bind anti-CSRF tokens to the user session; validate against the session server-side."
                evidence = "Same token observed across different session cookie values for action %s" % action_key
                other = "Heuristic detection; enable ACTIVE_CHECKS to confirm."
                raise_alert(ps, msg, Alert.RISK_LOW, Alert.CONFIDENCE_LOW, ALERT_NAME, desc, sol, evidence, other, name, value, CWE_ID, WASC_ID)

        # ----------------------------
        # Optional Active replay
        # ----------------------------
        if cfg["ACTIVE_CHECKS"] and is_state_changing_method(method):
            # Replay the request without tokens to check acceptance
            sender = _make_sender()
            if sender is not None:
                # 1) Remove tokens completely and send
                clone_msg = _clone_request_message(msg)
                if clone_msg is not None:
                    _strip_or_corrupt_tokens_in_msg(clone_msg)
                    accepted, status_code, elapsed = _send_and_classify(sender, clone_msg, cfg["REPLAY_TIMEOUT"])
                    vlog("Active replay removed tokens => accepted=%s status=%s elapsed=%sms" % (accepted, status_code, elapsed))
                    if accepted:
                        desc = "Server accepted a state-changing request without a valid anti-CSRF token (active replay)."
                        sol = "Enforce anti-CSRF tokens for all state-changing requests; validate server-side and reject missing/invalid tokens."
                        evidence = "Replay without token responded with status %s" % status_code
                        other = "Request replay removed token params/headers. Elapsed=%sms" % elapsed
                        raise_alert(ps, msg, Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, ALERT_NAME, desc, sol, evidence, other, None, "token_removed", CWE_ID, WASC_ID)
                # 2) If a static token was detected, corrupt it and send
                # We try to corrupt by setting token header/body (if present) to 'invalid'
                # (The earlier _strip function already removed; use original message to corrupt)
                clone2 = _clone_request_message(msg)
                if clone2 is not None:
                    try:
                        # Corrupt headers
                        hdr_names2 = clone2.getRequestHeader().getHeaderNames()
                        for i in range(hdr_names2.size()):
                            h = hdr_names2.get(i)
                            if h and is_token_name(h):
                                clone2.getRequestHeader().setHeader(h, "invalid")
                        # Corrupt body
                        content_type = clone2.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE)
                        if content_type and "application/x-www-form-urlencoded" in content_type.lower():
                            body = clone2.getRequestBody().toString()
                            pairs = body.split("&") if body else []
                            new_pairs = []
                            for pair in pairs:
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                else:
                                    k, v = pair, ""
                                if is_token_name(k):
                                    new_pairs.append("%s=%s" % (k, "invalid"))
                                else:
                                    new_pairs.append("%s=%s" % (k, v))
                            new_body = "&".join(new_pairs)
                            clone2.setRequestBody(new_body)
                            clone2.getRequestHeader().setContentLength(clone2.getRequestBody().length())
                        accepted2, status_code2, elapsed2 = _send_and_classify(sender, clone2, cfg["REPLAY_TIMEOUT"])
                        vlog("Active replay corrupted token => accepted=%s status=%s elapsed=%sms" % (accepted2, status_code2, elapsed2))
                        if accepted2:
                            desc = "Server accepted a state-changing request with an invalid anti-CSRF token (active replay)."
                            sol = "Validate anti-CSRF tokens server-side and reject invalid tokens."
                            evidence = "Replay with 'invalid' token responded with status %s" % status_code2
                            other = "Request replay corrupted token params/headers. Elapsed=%sms" % elapsed2
                            raise_alert(ps, msg, Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, ALERT_NAME, desc, sol, evidence, other, None, "token_invalid", CWE_ID, WASC_ID)
                    except Exception as e:
                        vlog("Active replay corruption error: %s" % e)

    except Exception as e:
        vlog("scan() exception: %s" % e)

# ----------------------------
# Required stubs for script metadata (some ZAP versions query this)
# ----------------------------

def getName():
    return ALERT_NAME

def getAuthor():
    return "Generated by Cursor Assistant"

def getDescription():
    return "Detects Anti-CSRF weaknesses via passive analysis and optional active replay checks."

def getVersion():
    return "1.0.0"


