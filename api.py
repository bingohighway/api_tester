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

# --- ENHANCED SENTINEL PATTERNS (Updated to fix | whoami and preserve previous fixes) ---
SUSPICIOUS_PATTERNS = {
    # SQL Injection 
    "SQLi Keyword/Tautology": re.compile(r"('|;|\b(OR|AND)\b\s*\d=\d|UNION\s+SELECT|SLEEP|USER\(\))", re.IGNORECASE),
    "SQLi Stacked/Comments": re.compile(r"(--|#|;|\/\*|\bDROP\b|\bDELETE\b|\bTRUNCATE\b)", re.IGNORECASE),
    "SQLi Quotes/Wildcard": re.compile(r"(\"|')(OR|AND)(\"|')|%'='", re.IGNORECASE),

    # Cross-Site Scripting
    "XSS Script/Event": re.compile(r"<\s*script|on(load|error|focus|click|mouseover)|javascript:", re.IGNORECASE),
    "XSS Tag Bypass": re.compile(r"<\s*(img|svg|body|iframe|a)\s+.*?=\s*[^>]*?alert", re.IGNORECASE),
    
    # Command & Path Traversal
    # Includes Windows path fix and explicit pipe command fix.
    "Path Traversal/Absolute": re.compile(
        r"(\.\.\/|\.\.\\|\/etc\/shadow|\\etc\\passwd|\/etc\/hosts|win\.ini|%2e%2e%2f|%252e%252e%252f)", 
        re.IGNORECASE
    ),
    # FIX: Explicitly target the pipe followed by whoami/known command.
    "Cmd Injection Pipe Bypass": re.compile(r"\|\s*(whoami|cat|ls|uname|id|reboot|ping)", re.IGNORECASE),
    
    # Command Injection (General Separators: &&, ||, ;, `, $(, \n, %0a)
    "Command Injection": re.compile(
        r"(&&|\|\||;|`|\$\(|\n|%0a)\s*(whoami|cat|ls|uname|id|reboot|ping)",
        re.IGNORECASE
    ),
    
    # SSRF & Header Injection
    "SSRF Metadata/Private IP": re.compile(r"169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.|localhost", re.IGNORECASE),
    "CRLF/Header Injection": re.compile(r"\%0a|%0d|Content-Length", re.IGNORECASE),

    # Deserialization & New Diagnostic Patterns
    "Deserialization Marker": re.compile(r"JRMI|cposix\nsystem|AAEAAAD", re.IGNORECASE),
    "Shellshock (CVE-2014-6271)": re.compile(r"\(\)\s*{.+?;\s*};?\s*\b(bash|sh)\b", re.IGNORECASE),
    "Log4j/JNDI Injection": re.compile(r"\$\{[^\}]+jndi:[^\}]+\}", re.IGNORECASE),
}
# ------------------------------------

API_CONTRACT = {
    "openapi": "3.0.0",
    "info": { "title": "WAF Test API", "version": "1.9.5", "description": "An intentionally permissive API to test WAFs and API Gateways." },
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
    # Standard headers (required)
    response.headers['Access-Control-Allow-Origin'] = '*';
    if args.tao: response.headers['Timing-Allow-Origin'] = '*'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Server/Handler identification header
    server_software = request.environ.get('SERVER_SOFTWARE', 'Unknown')
    response.headers['X-HTTP-Handler'] = server_software

    # Verbose response logging
    if args.verbose:
        CYAN = '\033[96m'; RESET = '\033[0m'
        response_body = response.get_data(as_text=True)
        # Log status and the first 200 characters of the body
        print(f"{CYAN}[VERBOSE] Sending Response (Status: {response.status_code}) with body: {response_body[:200]}...{RESET}", flush=True)

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
