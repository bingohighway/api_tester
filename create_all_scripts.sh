#!/bin/zsh

echo "Creating the API server file: api.py..."
cat > api.py << 'EOF'
#!/usr/bin/env python3
import time
import random
import string
import argparse
import json
import copy
from flask import Flask, request, jsonify, Response

# --- Argument Parsing ---
parser = argparse.ArgumentParser(
    description='A versatile Flask Test API for evaluating the capabilities of WAFs and API Gateways.',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    '--timing-allow-origin',
    dest='tao',
    action='store_true',
    help='Include the Timing-Allow-Origin: * header in all responses.'
)
args = parser.parse_args()

# --- Flask App Initialization ---
app = Flask(__name__)

# --- API Contract (OpenAPI 3.0) ---
API_CONTRACT = {
    "openapi": "3.0.0",
    "info": {
        "title": "WAF Test API",
        "version": "1.2.0",
        "description": "An API designed to test the capabilities of WAFs and API Gateways."
    },
    "paths": {
        "/usage": { "get": { "summary": "Provides a human-readable summary of all endpoints."}},
        "/capabilities": { "get": { "summary": "Describes all available endpoints in OpenAPI format."}},
        "/delay/{milliseconds}": { "get": { "summary": "Delays the response by a specified time.", "parameters": [{"name": "milliseconds", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 0, "maximum": 60000}}]}},
        "/headers": { "get": {"summary": "Reflects request headers."}},
        "/response-code/{code}": { "get": { "summary": "Returns a specific HTTP response code.", "parameters": [{"name": "code", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 100, "maximum": 599}}]}},
        "/tight-echo": { "post": { "summary": "Echos a string with a very strict contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "maxLength": 50, "pattern": "^[a-zA-Z]+$"}}}}}}}},
        "/loose-echo": { "post": { "summary": "Echos a string with a looser contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "maxLength": 50, "pattern": "^[a-zA-Z0-9]+$"}}}}}}}},
        "/random": { "get": { "summary": "Returns a random string with a strict contract length.", "parameters": [{"name": "length", "in": "query", "required": False, "schema": {"type": "integer", "default": 10, "maximum": 50}}]}},
        "/contract": { "get": {"summary": "Returns the full OpenAPI contract for this API."}},
        "/chars-contract": { "post": { "summary": "Accepts specific, 'suspicious' character strings enforced by contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string", "description": "Must be one of the allowed enumerated values.", "enum": ["!'=", "''#"]}}}}}}}},
        "/chars-no-contract": { "post": { "summary": "Accepts specific, 'suspicious' character strings not enforced by contract.", "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {"data": {"type": "string"}}}}}}}}
    }
}

@app.after_request
def add_custom_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    if args.tao:
        response.headers['Timing-Allow-Origin'] = '*'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

def _generate_limits_string(method_data):
    limits = []
    if 'parameters' in method_data:
        for param in method_data['parameters']:
            if 'schema' in param:
                schema = param['schema']
                if 'maximum' in schema: limits.append(f"Max value: {schema['maximum']}")
                if 'minimum' in schema: limits.append(f"Min value: {schema['minimum']}")
    elif 'requestBody' in method_data:
        try:
            schema = method_data['requestBody']['content']['application/json']['schema']['properties']['data']
            if 'maxLength' in schema: limits.append(f"Max length: {schema['maxLength']}")
            if 'pattern' in schema:
                if schema['pattern'] == '^[a-zA-Z]+$': limits.append("alphabetic chars only")
                elif schema['pattern'] == '^[a-zA-Z0-9]+$': limits.append("alphanumeric chars only")
            if 'enum' in schema: limits.append(f"must be one of: {schema['enum']}")
        except KeyError: pass
    return ", ".join(limits) if limits else "N/A"

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the WAF Test API. See /usage for a summary."})

@app.route('/usage')
def usage():
    examples = {
        '/usage': 'curl http://<your_api_host>/usage', '/capabilities': 'curl http://<your_api_host>/capabilities',
        '/delay/{milliseconds}': 'curl http://<your_api_host>/delay/500', '/headers': 'curl -H "X-Custom-Header: MyValue" http://<your_api_host>/headers',
        '/response-code/{code}': 'curl -i http://<your_api_host>/response-code/404',
        '/tight-echo': """curl -X POST -H "Content-Type: application/json" -d '{"data": "someText"}' http://<your_api_host>/tight-echo""",
        '/loose-echo': """curl -X POST -H "Content-Type: application/json" -d '{"data": "someText123"}' http://<your_api_host>/loose-echo""",
        '/random': 'curl "http://<your_api_host>/random?length=20"', '/contract': 'curl http://<your_api_host>/contract',
        '/chars-contract': """curl -X POST -H "Content-Type: application/json" -d '{"data": "''#"}' http://<your_api_host>/chars-contract""",
        '/chars-no-contract': """curl -X POST -H "Content-Type: application/json" -d '{"data": "!'="}' http://<your_api_host>/chars-no-contract"""
    }
    human_readable_summary = []
    for path, path_data in API_CONTRACT["paths"].items():
        for method, method_data in path_data.items():
            entry = {
                "endpoint": path, "http_method": method.upper(),
                "description": method_data.get("summary", "N/A"),
                "limits": _generate_limits_string(method_data),
                "example_call": examples.get(path, "N/A")
            }
            human_readable_summary.append(entry)
    return jsonify(human_readable_summary)

@app.route('/capabilities')
def capabilities():
    return jsonify(API_CONTRACT["paths"])

@app.route('/delay/<int:milliseconds>')
def delay(milliseconds):
    if milliseconds > 60000: return jsonify({"error": "Delay cannot exceed 60000 milliseconds."}), 400
    time.sleep(milliseconds / 1000.0)
    return jsonify({"status": "success", "delay_ms": milliseconds})
@app.route('/headers')
def headers():
    return jsonify({key: value for key, value in request.headers.items()})
@app.route('/response-code/<int:code>')
def response_code(code):
    if not 100 <= code <= 599: return jsonify({"error": "Invalid HTTP status code."}), 400
    return Response(f"Response with code {code}", status=code)
@app.route('/tight-echo', methods=['POST'])
def tight_echo():
    data = request.json.get('data', '')
    if len(data) > 200: return jsonify({"error": "Implementation limit: Data cannot exceed 200 characters."}), 413
    return jsonify({"echo": data})
@app.route('/loose-echo', methods=['POST'])
def loose_echo():
    data = request.json.get('data', '')
    if len(data) > 200: return jsonify({"error": "Implementation limit: Data cannot exceed 200 characters."}), 413
    return jsonify({"echo": data})
@app.route('/random')
def random_string():
    try: length = int(request.args.get('length', 10))
    except (ValueError, TypeError): return jsonify({"error": "Invalid length parameter. Must be an integer."}), 400
    if length > 1000: return jsonify({"error": "Implementation limit: Length cannot exceed 1000."}), 400
    return jsonify({"random_string": ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)), "length": length})
@app.route('/contract')
def contract():
    return jsonify(API_CONTRACT)
@app.route('/chars-contract', methods=['POST'])
def chars_contract():
    if request.json.get('data') in ["!'=", "''#"]: return jsonify({"status": "success"})
    return jsonify({"status": "failed", "reason": "Input does not match allowed values"}), 400
@app.route('/chars-no-contract', methods=['POST'])
def chars_no_contract():
    if request.json.get('data') in ["!'=", "''#"]: return jsonify({"status": "success"})
    return jsonify({"status": "failed", "reason": "Input does not match allowed values"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
EOF

echo "Creating the functional test script: tester.py..."
cat > tester.py << 'EOF'
import requests
import time
import json

BASE_URL = "http://127.0.0.1:5000"
HEADERS = {'User-Agent': 'WAF-Tester-Client/1.0'}

def print_test(name, success, details=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} | {name:50s} | {details}")

def test_usage_endpoint():
    print("\n--- Testing /usage Endpoint ---")
    try:
        response = requests.get(f"{BASE_URL}/usage", timeout=2)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert isinstance(data, list) and len(data) > 0, "Response is not a non-empty list"
        expected_keys = ["endpoint", "http_method", "description", "limits", "example_call"]
        assert all(key in data[0] for key in expected_keys), "A response entry is missing keys"
        print_test("Endpoint returns a valid, well-formed list", True, f"Found {len(data)} endpoints")
    except Exception as e:
        print_test("Endpoint returns a valid, well-formed list", False, f"Test failed: {e}")

def main():
    print(f"--- Starting API Functional Test Suite against {BASE_URL} ---")
    try:
        requests.get(BASE_URL, timeout=2)
    except requests.ConnectionError:
        print(f"❌ CRITICAL | API is not reachable at {BASE_URL}. Aborting tests.")
        return

    test_usage_endpoint()
    
    print("\n--- Test Suite Finished ---")

if __name__ == "__main__":
    main()
EOF

echo "Creating the performance test script: perf_tester.py..."
cat > perf_tester.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import json
import time
import datetime
import csv
import os
import argparse
from statistics import mean
from urllib.parse import urlparse
from collections import defaultdict
import tempfile

class Colors:
    GREEN = '\033[92m'; RESET = '\033[0m'; BOLD = '\033[1m'; CYAN = '\033[96m'
    YELLOW = '\033[93m'; DIM = '\033[2m'

BASE_URL = "http://127.0.0.1:5000"
ENDPOINTS_TO_TEST = [
    { "name": "GET /usage", "method": "GET", "path": "/usage", },
    { "name": "GET /capabilities", "method": "GET", "path": "/capabilities", },
    { "name": "GET /delay/200ms", "method": "GET", "path": "/delay/200", },
    { "name": "POST /tight-echo (valid)", "method": "POST", "path": "/tight-echo", "headers": {"Content-Type": "application/json"}, "body": {"data": "ValidAlpha"}},
    { "name": "GET /random?length=50", "method": "GET", "path": "/random?length=50", },
]

def measure_request(endpoint_config):
    full_url = f"{endpoint_config['base_url']}{endpoint_config['path']}"
    url_scheme = urlparse(full_url).scheme
    curl_format = json.dumps({ "status_code": "%{http_code}", "dns_time_s": "%{time_namelookup}", "tcp_time_s": "%{time_connect}", "tls_time_s": "%{time_appconnect}", "ttfb_s": "%{time_starttransfer}", "total_time_s": "%{time_total}" })
    with tempfile.NamedTemporaryFile(mode='w+', delete=True, encoding='utf-8') as body_file:
        command = [ "curl", "-s", "-o", body_file.name, "-w", curl_format, full_url ]
        command.extend(["-X", endpoint_config.get("method", "GET")])
        for key, value in endpoint_config.get("headers", {}).items():
            command.extend(["-H", f"{key}: {value}"])
        if "body" in endpoint_config:
            command.extend(["-d", json.dumps(endpoint_config["body"])])
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            body_file.seek(0)
            snippet = body_file.read(50).replace('\n', ' ')
            raw_data_s = json.loads(result.stdout)
            timing_data_ms = { "dns_time_ms": round(float(raw_data_s['dns_time_s'])*1000,3), "tcp_time_ms": round(float(raw_data_s['tcp_time_s'])*1000,3), "ttfb_ms": round(float(raw_data_s['ttfb_s'])*1000,3), "total_time_ms": round(float(raw_data_s['total_time_s'])*1000,3) }
            if url_scheme == 'https':
                tls_time_ms = round(float(raw_data_s['tls_time_s'])*1000,3)
                timing_data_ms['tls_time_ms'] = tls_time_ms
                timing_data_ms['tls_handshake_ms'] = round(tls_time_ms - timing_data_ms['tcp_time_ms'], 3)
            else:
                timing_data_ms['tls_time_ms'] = 'N/A'; timing_data_ms['tls_handshake_ms'] = 'N/A'
            return { "name": endpoint_config["name"], "timestamp": datetime.datetime.now().isoformat(), "status_code": raw_data_s['status_code'], "body_snippet": snippet, **timing_data_ms }
        except FileNotFoundError: print(f"{Colors.BOLD}ERROR: `curl` not found.{Colors.RESET}"); exit(1)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e: return { "name": endpoint_config["name"], "timestamp": datetime.datetime.now().isoformat(), "status_code": "000", "error": str(e), "body_snippet": "" }

def draw_dashboard(results, terminal_width, current_test_info=""):
    GRAPH_HEIGHT=7; Y_AXIS_LABEL_WIDTH=10; LOG_HISTORY_COUNT=3
    print('\033[2J\033[H', end=''); print(f"{Colors.BOLD}{Colors.GREEN}--- API Performance Dashboard (UTC {datetime.datetime.utcnow().strftime('%H:%M:%S')}) ---{Colors.RESET}"); print(f"{Colors.YELLOW}{current_test_info}{Colors.RESET}")
    if not results: return
    successful_results = [r for r in results if "error" not in r]
    avg_total = mean([r.get('total_time_ms', 0) for r in successful_results]) if successful_results else 0
    print(f"Total Requests: {Colors.CYAN}{len(results):<5}{Colors.RESET} Overall Avg Total Time: {Colors.CYAN}{avg_total:7.3f}ms{Colors.RESET}\n")
    grouped_results = defaultdict(list)
    for res in results: grouped_results[res['name']].append(res)
    for endpoint_config in ENDPOINTS_TO_TEST:
        endpoint_name = endpoint_config['name']; endpoint_results = grouped_results.get(endpoint_name, [])
        if not endpoint_results: continue
        num_runs = len(endpoint_results); print(f"{Colors.BOLD}{endpoint_name}{Colors.RESET} {Colors.DIM}({num_runs} runs total){Colors.RESET}")
        graph_width = terminal_width-Y_AXIS_LABEL_WIDTH-3; latencies = [r.get('total_time_ms',0) for r in endpoint_results]; plot_points = []
        if num_runs > graph_width:
            bucket_size = num_runs/graph_width
            for i in range(graph_width):
                start_index=int(i*bucket_size); end_index=int((i+1)*bucket_size); bucket_slice=latencies[start_index:end_index]
                if bucket_slice: plot_points.append(mean(bucket_slice))
                else: plot_points.append(latencies[start_index])
        else: plot_points=latencies
        min_lat = min(latencies) if latencies else 0; max_lat = max(latencies) if latencies else 1; lat_range = max_lat-min_lat if max_lat > min_lat else 1
        canvas = [[' ' for _ in range(len(plot_points))] for _ in range(GRAPH_HEIGHT)]
        for i, lat in enumerate(plot_points):
            y_pos = 0 
            if lat_range > 0: y_pos = int(((lat - min_lat) / lat_range) * (GRAPH_HEIGHT - 1))
            canvas[y_pos][i] = f"{Colors.GREEN}•{Colors.RESET}"
        for i in range(GRAPH_HEIGHT - 1, -1, -1):
            y_label_val = min_lat + (i / (GRAPH_HEIGHT - 1)) * lat_range; y_label = f"{y_label_val:{Y_AXIS_LABEL_WIDTH-3}.3f}ms"; print(f"{Colors.CYAN}{y_label}{Colors.RESET} | {''.join(canvas[i])}")
        axis_line = " "*(Y_AXIS_LABEL_WIDTH+1) + "└" + "─"*len(plot_points); print(axis_line)
        label_start="1"; label_mid=f"{num_runs//2}"; label_end=f"{num_runs}"; scale_labels=" "*(Y_AXIS_LABEL_WIDTH+1)
        if num_runs==1: scale_labels+=label_start
        elif num_runs > 1:
            mid_pos=(len(plot_points)//2)-(len(label_mid)//2); end_pos=len(plot_points)-len(label_end); scale_labels+=label_start
            if mid_pos > len(label_start): scale_labels += " "*(mid_pos-len(label_start))+label_mid
            if end_pos > mid_pos+len(label_mid): scale_labels += " "*(end_pos-(mid_pos+len(label_mid)))+label_end
        print(scale_labels)
        print(f"{Colors.DIM}  Recent Queries:{Colors.RESET}")
        for res in endpoint_results[-LOG_HISTORY_COUNT:]:
            status=res.get('status_code','ERR'); time_val=res.get('total_time_ms',0); status_color=Colors.GREEN if str(status).startswith('2') else Colors.YELLOW
            print(f"  - {res.get('timestamp','')[11:23]} | Status: {status_color}{status}{Colors.RESET} | Total: {time_val:.3f}ms")
        print("")

def main():
    parser = argparse.ArgumentParser(description="API Performance Measurement Tool.")
    parser.add_argument("--base-url", default=BASE_URL, help="Base URL of the API to test.")
    parser.add_argument("--runs", type=int, default=50, help="Number of requests to make *per endpoint*.")
    parser.add_argument("--delay", type=int, default=100, help="Delay between requests in milliseconds.")
    args = parser.parse_args()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_filename = f"performance_results_{timestamp}.csv"
    csv_headers = [ "timestamp", "name", "status_code", "body_snippet", "dns_time_ms", "tcp_time_ms", "tls_time_ms", "tls_handshake_ms", "ttfb_ms", "total_time_ms", "error" ]
    with open(csv_filename, "w", newline="", encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        all_results=[]; terminal_width=100
        try: terminal_width, _ = os.get_terminal_size()
        except OSError: pass
        total_endpoints = len(ENDPOINTS_TO_TEST); print(f"{Colors.GREEN}Starting performance test... Saved to {Colors.BOLD}{csv_filename}{Colors.RESET}"); time.sleep(2)
        try:
            for i, endpoint_config in enumerate(ENDPOINTS_TO_TEST):
                endpoint_config['base_url'] = args.base_url
                for run_num in range(args.runs):
                    current_test_info = f"Testing '{endpoint_config['name']}' ({i+1}/{total_endpoints}), Run {run_num+1}/{args.runs}"; result=measure_request(endpoint_config); all_results.append(result); writer.writerow({k: result.get(k,"") for k in csv_headers}); draw_dashboard(all_results, terminal_width, current_test_info); time.sleep(args.delay / 1000.0)
        except KeyboardInterrupt: print(f"\n\n{Colors.BOLD}Test interrupted.{Colors.RESET}")
        finally: print(f"\n{Colors.GREEN}Test finished. Results saved to {Colors.BOLD}{csv_filename}{Colors.RESET}")

if __name__ == "__main__":
    main()
EOF

echo "Creating API setup script: setup_api.sh..."
cat > setup_api.sh << 'EOF'
#!/bin/zsh
echo "--- Setting up Python environment for the Test API ---"
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed."
    exit 1
fi
python3 -m venv api_env
source api_env/bin/activate
echo "--- Installing Flask and Gunicorn ---"
pip install Flask gunicorn
echo "\n--- Setup Complete ---"
echo "To run the API server, activate the environment and use Gunicorn:"
echo "source api_env/bin/activate"
echo "gunicorn --bind 0.0.0.0:5000 --workers 4 api:app"
EOF

echo "Creating Testers setup script: setup_testers.sh..."
cat > setup_testers.sh << 'EOF'
#!/bin/zsh
echo "--- Setting up Python environment for the API Testers ---"
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed."
    exit 1
fi
python3 -m venv tester_env
source tester_env/bin/activate
echo "--- Installing Requests library ---"
pip install requests
echo "\n--- Setup Complete ---"
echo "To run the functional tester:"
echo "source tester_env/bin/activate"
echo "python3 tester.py"
echo "\nTo run the performance tester:"
echo "source tester_env/bin/activate"
echo "python3 perf_tester.py --runs 20 --delay 200"
EOF

chmod +x setup_api.sh
chmod +x setup_testers.sh

echo "\nAll script files created successfully!"
echo "You can now repeat the process for the README file."
