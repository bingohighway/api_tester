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
