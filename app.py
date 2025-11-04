from flask import request, make_response

# 1) Cross-domain script without integrity -> should trigger cross-domain inclusion alert
@app.route("/zap_test/cross_domain_no_integrity", methods=["GET"])
def zap_test_cross_domain_no_integrity():
    sid, resp = ensure_session()
    html = """
    <html><body>
      <h3>ZAP Test: cross-domain script WITHOUT integrity (should flag)</h3>
      <p>Script loaded from a third-party domain without integrity attribute.</p>

      <!-- External script from an unapproved domain and NO integrity attribute -->
      <script src="https://cdn.evil-example.com/malicious.js"></script>

      <!-- Inline dangerous JS tokens present too -->
      <script>
        // Dangerous tokens: eval, Function, document.write, innerHTML
        // (scanner should detect these in the response body)
        // eval("console.log('eval-run')");           // token present in source (commented)
        // var f = Function("return 'x'");           // Function token present
        // document.write('<div>doc.write()</div>');
        // document.getElementById('x').innerHTML = '<img src=x onerror=alert(1)>';
      </script>
    </body></html>
    """
    resp.set_data(html)
    return resp

# 2) Inline dangerous JS (no external script) -> should be detected by dangerous-functions scanner
@app.route("/zap_test/inline_dangerous", methods=["GET"])
def zap_test_inline_dangerous():
    sid, resp = ensure_session()
    html = """
    <html><body>
      <h3>ZAP Test: inline dangerous JS (should flag)</h3>

      <script>
        // Dangerous examples included verbatim so scanners find the tokens.
        // eval usage
        // NOTE: kept commented to avoid running in the browser automatically.
        // eval("alert('xss')");
        // setTimeout with string (legacy eval-like)
        // setTimeout("console.log('timeout-eval')", 1000);
        // setInterval("console.log('interval-eval')", 2000);
        // window.open usage example token
        // window.open('https://attacker.example.com','_blank');
        // AngularJS risky API token
        // $sce.trustAsHtml('<div>trusted</div>');
        // document.writeln('writing');
      </script>

      <p>This page contains many dangerous JS tokens in its source for detection.</p>
    </body></html>
    """
    resp.set_data(html)
    return resp

# 3) External script WITH integrity -> should NOT trigger cross-domain integrity alert (negative test)
@app.route("/zap_test/cross_domain_with_integrity", methods=["GET"])
def zap_test_cross_domain_with_integrity():
    sid, resp = ensure_session()
    # Example uses an integrity attribute (even if fake hash) — scanner should see presence of integrity and avoid the cross-domain alert.
    html = """
    <html><body>
      <h3>ZAP Test: cross-domain script WITH integrity (should not flag cross-domain integrity)</h3>
      <p>External script includes integrity attribute.</p>

      <script src="https://cdn.suspicious-example.com/okay.js"
              integrity="sha384-fakehashvalue"
              crossorigin="anonymous"></script>

      <p>Inline tokens intentionally minimal to avoid confusing the cross-domain test.</p>
    </body></html>
    """
    resp.set_data(html)
    return resp

# 4) Relative / same-origin script -> should NOT trigger cross-domain alert
@app.route("/zap_test/relative_same_origin", methods=["GET"])
def zap_test_relative_same_origin():
    sid, resp = ensure_session()
    html = """
    <html><body>
      <h3>ZAP Test: relative / same-origin script (should not flag)</h3>
      <p>Script src is relative (same-origin).</p>

      <!-- relative path -> not cross-domain -->
      <script src="/static/js/local-lib.js"></script>

      <!-- same-origin full URL -->
      <script src="http://{host}/static/js/also-local.js"></script>

      <script>
        // This inline script is benign (no dangerous tokens)
        // console.log('local script page');
      </script>
    </body></html>
    """.format(host=request.host)
    resp.set_data(html)
    return resp

# 5) Combined page: cross-domain + dangerous inline + approved domain (mix to test granularity)
@app.route("/zap_test/combined_examples", methods=["GET"])
def zap_test_combined_examples():
    sid, resp = ensure_session()
    html = """
    <html><body>
      <h3>ZAP Test: combined examples (should flag only the problematic ones)</h3>

      <!-- Approved domain (if your DOMAINS list contains 'cdn.safe-example.com' this will be ignored) -->
      <script src="https://cdn.safe-example.com/lib.js"></script>

      <!-- Unapproved third-party script WITHOUT integrity - should trigger -->
      <script src="https://another-evil.example.org/bad.js"></script>

      <!-- Dangerous inline tokens for DetectDangerousJS -->
      <script>
        // innerHTML token used in a way scanners will find
        // var junk = '<img src=x onerror=alert(1)>';
        // document.getElementById('out').innerHTML = junk;
      </script>

      <div id="out"></div>
    </body></html>
    """
    resp.set_data(html)
    return resp
