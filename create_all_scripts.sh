#!/bin/zsh

echo "Creating the PERMISSIVE API server file: api.py (Port 8000)..."
cat > api.py << 'EOF'
#!/usr/bin/env python3
import time, random, string, argparse, json, re
from flask import Flask, request, jsonify, Response
from urllib.parse import unquote

# --- Argument Parsing ---
parser = argparse.ArgumentParser(
    description='A versatile Flask Test API for evaluating WAFs and API Gateways.',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument('--timing-allow-origin', dest='tao', action='store_true', help='Include the Timing-Allow-Origin: * header in all responses.')
parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging to print the body of every request to the server's console.")
args = parser.parse_args()

# --- Flask App Initialization ---
app = Flask(__name__)

@app.before_request
def log_request_body():
    """If verbose mode is on, this logs the body of incoming requests."""
    if args.verbose and request.data:
        DIM = '\033[2m'; RESET = '\033[0m'
        body_to_log = ""
        try:
            body_to_log = json.dumps(request.get_json())
        except Exception:
            body_to_log = request.get_data(as_text=True)
        print(f"{DIM}[VERBOSE] Request to {request.path} received with body: {body_to_log}{RESET}", flush=True)

SUSPICIOUS_PATTERNS = {
    "SQLi Tautology": re.compile(r"'.*?OR.*?'\d+'\s*=\s*'\d+'", re.IGNORECASE),
    "SQLi Union": re.compile(r"UNION\s+SELECT", re.IGNORECASE),
    "Basic XSS": re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
    "Img XSS": re.compile(r"<img.*?src.*?onerror.*?>", re.IGNORECASE),
    "Path Traversal": re.compile(r"\.\./"),
    "Command Injection": re.compile(r"(&&|\|\||;|`)\s*(ls|cat|whoami|uname|ifconfig|ipconfig)", re.IGNORECASE),
}

API_CONTRACT = {
    "openapi": "3.0.0",
    "info": { "title": "WAF Test API", "version": "1.9.1", "description": "An intentionally permissive API to test WAFs and API Gateways." },
    "paths": {
        "/fuzz-target-weak": { "post": { "summary": "Fuzzing target with a weak/loose contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string"}}}}}}}},
        "/fuzz-target-strict": { "post": { "summary": "Fuzzing target with a strict (alphanumeric) contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "pattern": "^[a-zA-Z0-9]+$"}}}}}}}},
        "/hex-decode-check": { "post": { "summary": "Decodes a hex string and checks for suspicious patterns.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "pattern": "^[a-fA-F0-9]+$"}}}}}}}},
        "/url-decode-diagnostic": { "post": { "summary": "Decodes a URL-encoded string and returns a safe analysis.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string"}}}}}}}},
        "/pattern-check": { "post": { "summary": "Checks input against suspicious patterns (loose contract).", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string"}}}}}}}},
        "/pattern-check-contract": { "post": { "summary": "Checks input against suspicious patterns (strict contract).", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "pattern": "^[a-zA-Z0-9]+$", "maxLength": 50}}}}}}}},
        "/usage": { "get": { "summary": "Provides a human-readable summary of all endpoints."}},
        "/capabilities": { "get": { "summary": "Describes all available endpoints in OpenAPI format."}},
        "/delay/{milliseconds}": { "get": { "summary": "Delays the response by a specified time.", "parameters": [{"name": "milliseconds", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 0, "maximum": 60000}}]}},
        "/headers": { "get": {"summary": "Reflects request headers."}},
        "/response-code/{code}": { "get": { "summary": "Returns a specific HTTP response code.", "parameters": [{"name": "code", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 100, "maximum": 599}}]}},
        "/tight-echo": { "post": { "summary": "Echos a string with a very strict contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "maxLength": 50, "pattern": "^[a-zA-Z]+$"}}}}}}}},
        "/loose-echo": { "post": { "summary": "Echos a string with a looser contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "maxLength": 50, "pattern": "^[a-zA-Z0-9]+$"}}}}}}}},
        "/random": { "get": { "summary": "Returns a random string with a strict contract length.", "parameters": [{"name": "length", "in": "query", "required": False, "schema": {"type": "integer", "default": 10, "maximum": 50}}]}},
        "/contract": { "get": {"summary": "Returns the full OpenAPI contract for this API."}},
        "/chars-contract": { "post": { "summary": "Accepts only alphanumeric strings, enforced by contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "description": "Must contain only alphanumeric characters.","pattern": "^[a-zA-Z0-9]+$","maxLength": 50}}}}}}}}
    }
}

@app.after_request
def add_custom_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*';
    if args.tao: response.headers['Timing-Allow-Origin'] = '*'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    server_software = request.environ.get('SERVER_SOFTWARE', 'Unknown')
    response.headers['X-HTTP-Handler'] = server_software
    return response

# --- Endpoint Functions ---

@app.route('/')
def index(): return jsonify({"message": "Welcome. See /usage for details."})
@app.route('/usage')
def usage(): return jsonify(API_CONTRACT['paths'])
@app.route('/capabilities')
def capabilities(): return jsonify(API_CONTRACT['paths'])
@app.route('/contract')
def contract(): return jsonify(API_CONTRACT)
@app.route('/delay/<int:milliseconds>')
def delay(milliseconds):
    time.sleep(milliseconds / 1000.0)
    return jsonify({"status": "success", "delay_ms": milliseconds})
@app.route('/headers')
def headers(): return jsonify({key: value for key, value in request.headers.items()})
@app.route('/response-code/<int:code>')
def response_code(code):
    return Response(f"Response with code {code}", status=code)
@app.route('/tight-echo', methods=['POST'])
def tight_echo():
    return jsonify({"echo": request.json.get('data', '')})
@app.route('/loose-echo', methods=['POST'])
def loose_echo():
    return jsonify({"echo": request.json.get('data', '')})
@app.route('/random')
def random_string():
    try: length = int(request.args.get('length', 10))
    except (ValueError, TypeError): return jsonify({"error": "Invalid length parameter."}), 400
    return jsonify({"random_string": ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(length)), "length": length})
@app.route('/chars-contract', methods=['POST'])
def chars_contract():
    return jsonify({"status": "success", "message": "data received by API", "data_received": request.json.get('data')})
@app.route('/fuzz-target-weak', methods=['POST'])
def fuzz_target_weak():
    data = request.json.get('data', '')
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(data): return jsonify({"status": "pattern_received", "pattern_name": name})
    return jsonify({"status": "pattern_not_recognized"})
@app.route('/fuzz-target-strict', methods=['POST'])
def fuzz_target_strict():
    data = request.json.get('data', '')
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(data): return jsonify({"status": "pattern_received", "pattern_name": name})
    return jsonify({"status": "pattern_not_recognized"})
@app.route('/url-decode-diagnostic', methods=['POST'])
def url_decode_diagnostic():
    encoded_data = request.json.get('data', ''); decoded_string = unquote(encoded_data)
    analysis = {
        "contains_single_quote": "'" in decoded_string, "contains_space": " " in decoded_string,
        "contains_lt_gt": "<" in decoded_string or ">" in decoded_string,
        "contains_script_tag": bool(re.search(r"<script", decoded_string, re.IGNORECASE))
    }
    return jsonify({ "status": "analysis_complete", "original_length": len(encoded_data), "decoded_length": len(decoded_string), "analysis": analysis })
@app.route('/hex-decode-check', methods=['POST'])
def hex_decode_check():
    hex_data = request.json.get('data','');
    try: decoded_bytes = bytes.fromhex(hex_data); decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
    except (ValueError,TypeError): return jsonify({"error":"Invalid hex"}),400
    for n,p in SUSPICIOUS_PATTERNS.items():
        if p.search(decoded_string): return jsonify({"status":"match_found_after_decode","pattern_name":n})
    return jsonify({"status":"no_match_found_after_decode"})
@app.route('/pattern-check', methods=['POST'])
def pattern_check():
    data = request.json.get('data', '');
    if not isinstance(data, str): return jsonify({"error": "Invalid input format"}), 400
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(data): return jsonify({"status": "match_found", "pattern_name": name})
    return jsonify({"status": "no_match_found"})
@app.route('/pattern-check-contract', methods=['POST'])
def pattern_check_contract():
    data = request.json.get('data', '');
    if not isinstance(data, str): return jsonify({"error": "Invalid input format"}), 400
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(data): return jsonify({"status": "match_found", "pattern_name": name})
    return jsonify({"status": "no_match_found"})

if __name__ == '__main__':
    # Flask's built-in development server (Werkzeug), highly permissive. Now runs on 8000.
    app.run(debug=True, port=8000, host='0.0.0.0')
EOF

echo "Creating the functional test script: tester.py (Port 8000)..."
cat > tester.py << 'EOF'
import requests, time, json
from urllib.parse import quote

BASE_URL = "http://127.0.0.1:8000" # <-- MODIFIED TO PORT 8000
HEADERS = {'User-Agent': 'WAF-Tester-Client/1.0', 'Content-Type': 'application/json'}

def print_test(name, success, details=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} | {name:50s} | {details}")

def test_usage_endpoint():
    print("\n--- Testing /usage Endpoint ---")
    try:
        response = requests.get(f"{BASE_URL}/usage", timeout=2)
        assert response.status_code == 200 and isinstance(response.json(), list)
        print_test("Endpoint returns a valid list", True, f"Found {len(response.json())} endpoints")
    except Exception as e:
        print_test("Endpoint returns a valid list", False, f"Test failed: {e}")

def test_delay():
    print("\n--- Testing /delay Endpoint ---")
    delay_ms = 200; url = f"{BASE_URL}/delay/{delay_ms}"; start_time = time.time()
    try:
        response = requests.get(url, timeout=2); end_time = time.time(); duration_s = end_time - start_time
        success = response.status_code == 200 and (delay_ms / 1000) <= duration_s < (delay_ms / 1000 + 0.5)
        print_test("Response delay is accurate", success, f"Expected ~{delay_ms}ms, Got {duration_s*1000:.2f}ms")
    except requests.exceptions.RequestException as e:
        print_test("Response delay is accurate", False, f"Request failed: {e}")

def test_headers():
    print("\n--- Testing /headers Endpoint ---")
    try:
        response = requests.get(f"{BASE_URL}/headers", headers=HEADERS)
        data = response.json()
        success = response.status_code == 200 and data.get("User-Agent") == HEADERS['User-Agent']
        print_test("Reflects custom User-Agent header", success, f"Sent: {HEADERS['User-Agent']}")
    except requests.exceptions.RequestException as e:
        print_test("Reflects custom User-Agent header", False, f"Request failed: {e}")

def test_response_codes():
    print("\n--- Testing /response-code Endpoint ---")
    for code in [200, 404, 503]:
        try:
            response = requests.get(f"{BASE_URL}/response-code/{code}", timeout=2)
            print_test(f"Responds with HTTP {code}", response.status_code == code)
        except requests.exceptions.RequestException as e:
            print_test(f"Responds with HTTP {code}", False, f"Request failed: {e}")

def test_contract_security():
    print("\n--- Testing Contract-Based Security (/chars-contract) ---")
    try:
        res = requests.post(f"{BASE_URL}/chars-contract", json={"data": "!'="}, timeout=2)
        if res.status_code != 200:
            print_test("Suspicious characters blocked by contract", True, f"Correctly blocked with status {res.status_code}")
        else:
            print_test("Suspicious characters allowed by contract", False, "FAIL: WAF did not enforce contract, API received data.")
    except requests.exceptions.RequestException:
        print_test("Suspicious characters blocked by contract", True, "Request failed, likely blocked by WAF/Gateway")

def test_pattern_blocking():
    print("\n--- Testing Pattern-Matching ---")
    suspicious_payload = {"data": "1' OR '1'='1'"}
    try:
        res = requests.post(f"{BASE_URL}/pattern-check", json=suspicious_payload, timeout=2)
        if res.status_code != 200:
            print_test("Suspicious pattern blocked by signature", True, f"Blocked with status {res.status_code}")
        else:
            p_name = res.json().get("pattern_name", "N/A")
            print_test("Suspicious pattern NOT blocked by signature", False, f"WAF failed, API matched: {p_name}")
    except requests.exceptions.RequestException:
        print_test("Suspicious pattern blocked by signature", True, "Request failed, likely blocked by WAF")

def test_encoded_bypass_attempt():
    print("\n--- Testing Evasion via Encoding ---")
    hex_payload = "' OR '1'='1".encode('utf-8').hex()
    url_payload = quote("<script>alert('xss')</script>")
    try:
        res = requests.post(f"{BASE_URL}/hex-decode-check", json={"data": hex_payload}, timeout=2)
        if res.status_code != 200:
            print_test("Hex-encoded attack pattern blocked", True, f"Blocked with status {res.status_code}")
        else:
            p_name = res.json().get("pattern_name", "N/A")
            print_test("Hex-encoded attack pattern BYPASSED WAF", False, f"WAF failed, API decoded and matched: {p_name}")
    except requests.exceptions.RequestException:
        print_test("Hex-encoded attack pattern blocked", True, "Request failed, likely blocked by WAF/Gateway")
    try:
        res = requests.post(f"{BASE_URL}/url-decode-diagnostic", json={"data": url_payload}, timeout=2)
        if res.status_code != 200:
            print_test("URL-encoded attack pattern blocked", True, f"Blocked with status {res.status_code}")
        else:
            print_test("URL-encoded attack pattern BYPASSED WAF", False, "WAF failed to normalize and block payload")
    except requests.exceptions.RequestException:
        print_test("URL-encoded attack pattern blocked", True, "Request failed, likely blocked by WAF/Gateway")

def main():
    print(f"--- Starting API Functional Test Suite against {BASE_URL} ---")
    try: requests.get(BASE_URL, timeout=2)
    except requests.ConnectionError: print(f"❌ CRITICAL | API is not reachable at {BASE_URL}."); return
    
    test_usage_endpoint()
    test_delay()
    test_headers()
    test_response_codes()
    test_contract_security()
    test_pattern_blocking()
    test_encoded_bypass_attempt()
    
    print("\n--- Test Suite Finished ---")

if __name__ == "__main__":
    main()
EOF

echo "Creating the WAF fuzzer script: fuzzer.py (Port 8000)..."
cat > fuzzer.py << 'EOF'
#!/usr/bin/env python3
import requests, time, json, datetime, csv, argparse

BASE_URL = "http://127.0.0.1:8000" # <-- MODIFIED TO PORT 8000
HEADERS = {'User-Agent': 'WAF-Fuzzer/1.0', 'Content-Type': 'application/json'}
class Colors:
    GREEN = '\033[92m'; RESET = '\033[0m'; BOLD = '\033[1m'; RED = '\033[91m'; DIM = '\033[2m'
PAYLOADS = [
    {"type": "SQLi", "description": "Classic Tautology", "payload": "' OR 1=1--"},
    {"type": "SQLi", "description": "Tautology with Comment", "payload": "' OR 'a'='a"},
    {"type": "SQLi", "description": "Boolean-based Blind", "payload": "AND 1=1"},
    {"type": "SQLi", "description": "UNION Statement", "payload": "UNION SELECT user, password FROM users"},
    {"type": "SQLi", "description": "Stacked Query", "payload": "'; DROP TABLE members;--"},
    {"type": "SQLi", "description": "Error-based", "payload": "OR 1=CAST(CONCAT(0x7e,(SELECT user())) AS SIGNED)"},
    {"type": "SQLi", "description": "Time-based Blind", "payload": "OR IF(1=1, SLEEP(5), 0)"},
    {"type": "SQLi", "description": "Authentication Bypass", "payload": "admin'--"},
    {"type": "SQLi", "description": "Double Quote Tautology", "payload": "\" OR 1=1--"},
    {"type": "SQLi", "description": "Wildcard Bypass", "payload": "' OR '%'='"},
    {"type": "XSS", "description": "Basic Script Tag", "payload": "<script>alert('XSS')</script>"},
    {"type": "XSS", "description": "Image OnError", "payload": "<img src=x onerror=alert(document.cookie)>"},
    {"type": "XSS", "description": "Body OnLoad", "payload": "<body onload=alert(1)>"},
    {"type": "XSS", "description": "SVG OnLoad", "payload": "<svg/onload=alert(1)>"},
    {"type": "XSS", "description": "Iframe Source", "payload": "<iframe src=\"javascript:alert(1)\">"},
    {"type": "XSS", "description": "Case Insensitive", "payload": "<ScRiPt>alert(1)</sCrIpT>"},
    {"type": "XSS", "description": "No Closing Tag", "payload": "<script src=http://evil.com/xss.js>"},
    {"type": "XSS", "description": "Anchor Href", "payload": "<a href=\"javascript:alert(1)\">Click me</a>"},
    {"type": "XSS", "description": "Input Autofocus", "payload": "<input onfocus=alert(1) autofocus>"},
    {"type": "XSS", "description": "Video Poster", "payload": "<video poster=javascript:alert(1)>"},
    {"type": "Cmd Injection", "description": "Simple Pipe", "payload": "| whoami"},
    {"type": "Cmd Injection", "description": "Semicolon Separator", "payload": "; ls -la /"},
    {"type": "Cmd Injection", "description": "Logical AND", "payload": "&& cat /etc/passwd"},
    {"type": "Cmd Injection", "description": "Logical OR", "payload": "|| ping -c 4 evil.com"},
    {"type": "Cmd Injection", "description": "Backticks", "payload": "`uname -a`"},
    {"type": "Cmd Injection", "description": "Command Substitution", "payload": "$(reboot)"},
    {"type": "Cmd Injection", "description": "Newline Separator", "payload": "id\ncat /etc/hosts", "gunicorn_block": True},
    {"type": "Path Traversal", "description": "Parent Directory", "payload": "../../etc/passwd"},
    {"type": "Path Traversal", "description": "Root Directory", "payload": "/etc/shadow"},
    {"type": "Path Traversal", "description": "Windows Directory", "payload": "..\\..\\..\\windows\\win.ini"},
    {"type": "Path Traversal", "description": "URL Encoded", "payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
    {"type": "Path Traversal", "description": "Double URL Encoded", "payload": "%252e%252e%252fetc%252fpasswd"},
    {"type": "Path Traversal", "description": "Null Byte", "payload": "../../etc/passwd%00"},
    {"type": "SSRF", "description": "Localhost", "payload": "http://localhost/admin"},
    {"type": "SSRF", "description": "127.0.0.1", "payload": "http://127.0.0.1:8080"},
    {"type": "SSRF", "description": "AWS Metadata Service", "payload": "http://169.254.169.254/latest/meta-data/"},
    {"type": "SSRF", "description": "GCP Metadata Service", "payload": "http://metadata.google.internal/computeMetadata/v1/"},
    {"type": "SSRF", "description": "Internal IP", "payload": "http://10.0.0.1/"},
    {"type": "Log Injection", "description": "Newline Characters", "payload": "user=guest%0a%0dmalicious_log_entry", "gunicorn_block": True},
    {"type": "HTTP Header Inj", "description": "Response Splitting", "payload": "value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK", "gunicorn_block": True},
    {"type": "Deserialization", "description": "Java RMI Header", "payload": "JRMI", "gunicorn_block": True},
    {"type": "Deserialization", "description": "Python Pickle", "payload": "cposix\nsystem\n", "gunicorn_block": True},
    {"type": "Deserialization", "description": ".NET Gadget", "payload": "AAEAAAD/////AQAAAAAAAAAMAgAAAFBTeXN0ZW0", "gunicorn_block": True},
]
def print_result(attack_info, contract_type, result, details=""):
    result_color = Colors.GREEN if result == "BLOCKED" else Colors.RED
    note = ""
    if result == "BLOCKED" and attack_info.get("gunicorn_block"): note = f" {Colors.DIM}(Expected Gunicorn block){Colors.RESET}"
    print(f"  [{attack_info['type']:18s}] [{contract_type:14s}] Result: {result_color}{result}{Colors.RESET} | {details}{note}")
def run_test(endpoint, contract_type, attack_info, writer, verbose=False):
    payload = attack_info['payload']; full_url = f"{BASE_URL}{endpoint}"; json_body = {"data": payload}
    if verbose: print(f"{Colors.DIM}  ------------------------------------------------------\n  VERBOSE: Sending Request...\n  - URL:     {full_url}\n  - Method:  POST\n  - Headers: {json.dumps(HEADERS)}\n  - Body:    {json.dumps(json_body)}\n  ------------------------------------------------------{Colors.RESET}")
    result_data = { "timestamp": datetime.datetime.utcnow().isoformat(), "attack_type": attack_info['type'], "description": attack_info['description'], "payload": payload, "contract_type": contract_type, "expected_gunicorn_block": attack_info.get("gunicorn_block", False), "http_handler": "N/A", "result": "", "http_status": "N/A", "response_body": "" }
    try:
        res = requests.post(full_url, json=json_body, headers=HEADERS, timeout=2)
        result_data["http_status"] = res.status_code; result_data["http_handler"] = res.headers.get('X-HTTP-Handler', 'N/A'); response_json = {}
        try: response_json = res.json(); result_data["response_body"] = json.dumps(response_json)
        except json.JSONDecodeError: result_data["response_body"] = res.text[:200]
        if response_json.get("status") == "pattern_received":
            result_data["result"] = "ALLOWED"; print_result(attack_info, contract_type, "ALLOWED", f"WAF FAILED - API received: {response_json.get('pattern_name', 'N/A')}")
        else:
            result_data["result"] = "BLOCKED"; print_result(attack_info, contract_type, "BLOCKED", f"WAF Block Page or API rejection (Status: {res.status_code})")
    except requests.exceptions.RequestException as e:
        result_data["result"] = "BLOCKED"; result_data["response_body"] = str(e); print_result(attack_info, contract_type, "BLOCKED", "Request failed (No HTTP Response)")
    writer.writerow(result_data)
def main():
    parser = argparse.ArgumentParser(description="A comprehensive fuzzer to test WAF efficacy.")
    parser.add_argument("--delay", type=int, default=100, help="Delay in milliseconds between each payload test.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode to print full request details.")
    args = parser.parse_args(); print(f"{Colors.BOLD}--- Starting WAF Efficacy Fuzzer against {BASE_URL} ---\n")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"); csv_filename = f"fuzz_results_{timestamp}.csv"
    csv_headers = ["timestamp", "attack_type", "description", "payload", "contract_type", "expected_gunicorn_block", "result", "http_status", "http_handler", "response_body"]
    with open(csv_filename, "w", newline="", encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers); writer.writeheader()
        total_payloads = len(PAYLOADS)
        for i, attack in enumerate(PAYLOADS):
            print(f"Testing Payload {i+1}/{total_payloads}: {Colors.BOLD}{attack['payload']}{Colors.RESET} ({attack['description']})")
            run_test("/fuzz-target-weak", "Weak Contract", attack, writer, args.verbose)
            run_test("/fuzz-target-strict", "Strict Contract", attack, writer, args.verbose)
            print("-" * 80); time.sleep(args.delay / 1000.0)
    print(f"\n{Colors.GREEN}Fuzzing complete. Full results saved to {Colors.BOLD}{csv_filename}{Colors.RESET}")
if __name__ == "__main__": main()
EOF

echo "Creating performance test script: perf_tester.py (Port 8000)..."
cat > perf_tester.py << 'EOF'
#!/usr/bin/env python3
import subprocess,json,time,datetime,csv,os,argparse,tempfile
from statistics import mean
from urllib.parse import urlparse, quote
from collections import defaultdict
class Colors:
    GREEN='\033[92m';RESET='\033[0m';BOLD='\033[1m';CYAN='\033[96m';YELLOW='\033[93m';DIM='\033[2m'
BASE_URL="http://127.0.0.1:8000" # <-- MODIFIED TO PORT 8000
ENDPOINTS_TO_TEST=[
    {"name":"GET /usage","method":"GET","path":"/usage"},
    {"name":"POST /hex-decode-check", "method":"POST", "path":"/hex-decode-check", "headers":{"Content-Type":"application/json"}, "body":{"data": "68656c6c6f"}},
    {"name":"POST /url-decode-diagnostic", "method":"POST", "path":"/url-decode-diagnostic", "headers":{"Content-Type":"application/json"}, "body":{"data": quote("hello world")}},
    {"name":"GET /delay/200ms", "method":"GET", "path":"/delay/200"},
]
def measure_request(endpoint_config):
    full_url=f"{endpoint_config['base_url']}{endpoint_config['path']}";url_scheme=urlparse(full_url).scheme;curl_format=json.dumps({"status_code":"%{http_code}","dns_time_s":"%{time_namelookup}","tcp_time_s":"%{time_connect}","tls_time_s":"%{time_appconnect}","ttfb_s":"%{time_starttransfer}","total_time_s":"%{time_total}","http_handler_header":"%{header_out}","http_response_header":"%{header_in}"})
    with tempfile.NamedTemporaryFile(mode='w+',delete=True,encoding='utf-8') as body_file:
        command=["curl","-s","-o",body_file.name,"-w",curl_format,full_url,"--include"];command.extend(["-X",endpoint_config.get("method","GET")])
        for key,value in endpoint_config.get("headers",{}).items():command.extend(["-H",f"{key}: {value}"])
        if"body"in endpoint_config:command.extend(["-d",json.dumps(endpoint_config["body"])])
        try:
            result=subprocess.run(command,capture_output=True,text=True,check=True);body_file.seek(0);
            body_content=body_file.read();
            snippet=body_content.split('\r\n\r\n')[-1][:50].replace('\n',' ');
            raw_data_s=json.loads(result.stdout);
            
            # Extract X-HTTP-Handler from response headers
            handler_header = 'N/A'
            response_headers_raw = raw_data_s.get('http_response_header', '')
            for line in response_headers_raw.split('\n'):
                if line.startswith('X-Http-Handler:'):
                    handler_header = line.split(': ')[1].strip()
                    break

            timing_data_ms={"dns_time_ms":round(float(raw_data_s['dns_time_s'])*1000,3),"tcp_time_ms":round(float(raw_data_s['tcp_time_s'])*1000,3),"ttfb_ms":round(float(raw_data_s['ttfb_s'])*1000,3),"total_time_ms":round(float(raw_data_s['total_time_s'])*1000,3)}
            if url_scheme=='https':
                tls_time_ms=round(float(raw_data_s['tls_time_s'])*1000,3);timing_data_ms['tls_time_ms']=tls_time_ms;timing_data_ms['tls_handshake_ms']=round(tls_time_ms-timing_data_ms['tcp_time_ms'],3)
            else:
                timing_data_ms['tls_time_ms']='N/A';timing_data_ms['tls_handshake_ms']='N/A'
            return{"name":endpoint_config["name"],"timestamp":datetime.datetime.now().isoformat(),"status_code":raw_data_s['status_code'],"body_snippet":snippet,"http_handler":handler_header,**timing_data_ms}
        except FileNotFoundError:print(f"{Colors.BOLD}ERROR: `curl` not found.{Colors.RESET}");exit(1)
        except(subprocess.CalledProcessError,json.JSONDecodeError)as e:return{"name":endpoint_config["name"],"timestamp":datetime.datetime.now().isoformat(),"status_code":"000","error":str(e),"body_snippet":""}
def draw_dashboard(results,terminal_width,current_test_info=""):
    GRAPH_HEIGHT=7;Y_AXIS_LABEL_WIDTH=10;LOG_HISTORY_COUNT=3;print('\033[2J\033[H',end='');print(f"{Colors.BOLD}{Colors.GREEN}--- API Performance Dashboard (UTC {datetime.datetime.utcnow().strftime('%H:%M:%S')}) ---{Colors.RESET}");print(f"{Colors.YELLOW}{current_test_info}{Colors.RESET}")
    if not results:return
    successful_results=[r for r in results if"error"not in r];avg_total=mean([r.get('total_time_ms',0)for r in successful_results])if successful_results else 0;print(f"Total Requests: {Colors.CYAN}{len(results):<5}{Colors.RESET} Overall Avg Total Time: {Colors.CYAN}{avg_total:7.3f}ms{Colors.RESET}\n")
    grouped_results=defaultdict(list);
    for res in results:grouped_results[res['name']].append(res)
    for endpoint_config in ENDPOINTS_TO_TEST:
        endpoint_name=endpoint_config['name'];endpoint_results=grouped_results.get(endpoint_name,[])
        if not endpoint_results:continue
        num_runs=len(endpoint_results);print(f"{Colors.BOLD}{endpoint_name}{Colors.RESET} {Colors.DIM}({num_runs} runs total){Colors.RESET}");graph_width=terminal_width-Y_AXIS_LABEL_WIDTH-3;latencies=[r.get('total_time_ms',0)for r in endpoint_results];plot_points=[]
        if num_runs>graph_width:
            bucket_size=num_runs/graph_width
            for i in range(graph_width):
                start_index=int(i*bucket_size);end_index=int((i+1)*bucket_size);bucket_slice=latencies[start_index:end_index]
                if bucket_slice:plot_points.append(mean(bucket_slice))
                else:plot_points.append(latencies[start_index])
        else:plot_points=latencies
        min_lat=min(latencies)if latencies else 0;max_lat=max(latencies)if latencies else 1;lat_range=max_lat-min_lat if max_lat > min_lat else 1;canvas=[[' 'for _ in range(len(plot_points))]for _ in range(GRAPH_HEIGHT)]
        for i,lat in enumerate(plot_points):
            y_pos=0 
            if lat_range > 0:y_pos=int(((lat-min_lat)/lat_range)*(GRAPH_HEIGHT-1))
            canvas[y_pos][i]=f"{Colors.GREEN}•{Colors.RESET}"
        for i in range(GRAPH_HEIGHT - 1,-1,-1):
            y_label_val=min_lat+(i/(GRAPH_HEIGHT-1))*lat_range;y_label=f"{y_label_val:{Y_AXIS_LABEL_WIDTH-3}.3f}ms";print(f"{Colors.CYAN}{y_label}{Colors.RESET} | {''.join(canvas[i])}")
        axis_line=" "*(Y_AXIS_LABEL_WIDTH+1)+"└"+"─"*len(plot_points);print(axis_line);label_start="1";label_mid=f"{num_runs//2}";label_end=f"{num_runs}";scale_labels=" "*(Y_AXIS_LABEL_WIDTH+1)
        if num_runs==1:scale_labels+=label_start
        elif num_runs>1:
            mid_pos=(len(plot_points)//2)-(len(label_mid)//2);end_pos=len(plot_points)-len(label_end);scale_labels+=label_start
            if mid_pos>len(label_start):scale_labels+=" "*(mid_pos-len(label_start))+label_mid
            if end_pos>mid_pos+len(label_mid):scale_labels+=" "*(end_pos-(mid_pos+len(label_mid)))+label_end
        print(scale_labels);print(f"{Colors.DIM}  Recent Queries:{Colors.RESET}")
        for res in endpoint_results[-LOG_HISTORY_COUNT:]:
            status=res.get('status_code','ERR');time_val=res.get('total_time_ms',0);status_color=Colors.GREEN if str(status).startswith('2')else Colors.YELLOW;print(f"  - {res.get('timestamp','')[11:23]} | Status: {status_color}{status}{Colors.RESET} | Total: {time_val:.3f}ms | Handler: {res.get('http_handler')}")
        print("")
def main():
    parser=argparse.ArgumentParser(description="API Performance Measurement Tool.");parser.add_argument("--base-url",default=BASE_URL,help="Base URL of the API to test.");parser.add_argument("--runs",type=int,default=50,help="Number of requests to make *per endpoint*.");parser.add_argument("--delay",type=int,default=100,help="Delay between requests in milliseconds.");args=parser.parse_args();timestamp=datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S");csv_filename=f"performance_results_{timestamp}.csv"
    csv_headers=["timestamp","name","status_code","body_snippet","http_handler","dns_time_ms","tcp_time_ms","tls_time_ms","tls_handshake_ms","ttfb_ms","total_time_ms","error"]
    with open(csv_filename,"w",newline="",encoding='utf-8')as f:
        writer=csv.DictWriter(f,fieldnames=csv_headers);writer.writeheader();all_results=[];terminal_width=100
        try:terminal_width,_=os.get_terminal_size()
        except OSError:pass
        total_endpoints=len(ENDPOINTS_TO_TEST);print(f"{Colors.GREEN}Starting performance test... Saved to {Colors.BOLD}{csv_filename}{Colors.RESET}");time.sleep(2)
        try:
            for i,endpoint_config in enumerate(ENDPOINTS_TO_TEST):
                endpoint_config['base_url']=args.base_url
                for run_num in range(args.runs):
                    current_test_info=f"Testing '{endpoint_config['name']}' ({i+1}/{total_endpoints}), Run {run_num+1}/{args.runs}";result=measure_request(endpoint_config);all_results.append(result);writer.writerow({k:result.get(k,"")for k in csv_headers});draw_dashboard(all_results,terminal_width,current_test_info);time.sleep(args.delay/1000.0)
        except KeyboardInterrupt:print(f"\n\n{Colors.BOLD}Test interrupted.{Colors.RESET}")
        finally:print(f"\n{Colors.GREEN}Test finished. Results saved to {Colors.BOLD}{csv_filename}{Colors.RESET}")
if __name__=="__main__":
    main()
EOF

echo "Creating API setup script: setup_api.sh (Port 8000)..."
cat > setup_api.sh << 'EOF'
#!/bin/zsh
echo "--- Setting up Python environment for the Test API ---"
if ! command -v python3 &> /dev/null; then echo "Error: python3 is not installed."; exit 1; fi
python3 -m venv api_env; source api_env/bin/activate
echo "--- Installing Flask and Gunicorn ---"; pip install Flask gunicorn
echo "\n--- Setup Complete ---"
echo "You can now run the API server in one of two modes:"
echo
echo "\033[1mMode 1 (Default - Production Style with Gunicorn):\033[0m"
echo "Use this to test with Gunicorn's baseline security."
echo "  source api_env/bin/activate"
echo "  gunicorn --bind 0.0.0.0:8000 --workers 4 api:app" # <-- MODIFIED TO PORT 8000
echo
echo "\033[1mMode 1 (Verbose - Production Style with Gunicorn):\033[0m"
echo "  source api_env/bin/activate"
echo "  gunicorn --bind 0.0.0.0:8000 --workers 4 api:app -- --verbose" # <-- MODIFIED TO PORT 8000
echo
echo "\033[1mMode 2 (Permissive - Development Style):\033[0m"
echo "Use this for pure WAF testing without Gunicorn's interference."
echo "  source api_env/bin/activate"
echo "  python3 api.py --verbose"
EOF

echo "Creating Testers setup script: setup_testers.sh (Port 8000)..."
cat > setup_testers.sh << 'EOF'
#!/bin/zsh
echo "--- Setting up Python environment for the API Testers ---"
if ! command -v python3 &> /dev/null; then echo "Error: python3 is not installed."; exit 1; fi
python3 -m venv tester_env; source tester_env/bin/activate
echo "--- Installing Requests library ---"; pip install requests
echo "\n--- Setup Complete ---"
echo "To run the functional tester:"; echo "  source tester_env/bin/activate"; echo "  python3 tester.py"
echo "\nTo run the WAF fuzzer:"; echo "  source tester_env/bin/activate"; echo "  python3 fuzzer.py"
echo "\nTo run the performance tester:"; echo "  source tester_env/bin/activate"; echo "  python3 perf_tester.py"
EOF

chmod +x setup_api.sh
chmod +x setup_testers.sh

echo "\nAll script files have been regenerated and are now set to use PORT 8000!"
