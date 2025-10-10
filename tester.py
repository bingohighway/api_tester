import requests
import time
import json

BASE_URL = "http://127.0.0.1:5000"
HEADERS = {'User-Agent': 'WAF-Tester-Client/1.0'}

def print_test(name, success, details=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} | {name:50s} | {details}")

def test_pattern_blocking():
    print("\n--- Testing Pattern-Matching & Contract Blocking ---")
    suspicious_payload = {"data": "1' OR '1'='1'"}
    
    # Test 1: Send to the endpoint with the LOOSE contract (/pattern-check)
    # A WAF should block this based on its SIGNATURE rules.
    try:
        res = requests.post(f"{BASE_URL}/pattern-check", json=suspicious_payload, timeout=2)
        if res.status_code != 200:
            print_test("Suspicious pattern blocked by signature", True, f"Blocked with status {res.status_code}")
        else:
            p_name = res.json().get("pattern_name", "N/A")
            print_test("Suspicious pattern NOT blocked by signature", False, f"WAF failed, API matched: {p_name}")
    except requests.exceptions.RequestException:
        print_test("Suspicious pattern blocked by signature", True, "Request failed, likely blocked by WAF")

    # <-- NEW TEST -->
    # Test 2: Send to the endpoint with the STRICT contract (/pattern-check-contract)
    # A WAF should block this based on CONTRACT ENFORCEMENT because it's not alphanumeric.
    try:
        res = requests.post(f"{BASE_URL}/pattern-check-contract", json=suspicious_payload, timeout=2)
        if res.status_code != 200:
            print_test("Suspicious pattern blocked by contract", True, f"Blocked with status {res.status_code}")
        else:
            p_name = res.json().get("pattern_name", "N/A")
            print_test("Suspicious pattern NOT blocked by contract", False, f"WAF failed, API matched: {p_name}")
    except requests.exceptions.RequestException:
        print_test("Suspicious pattern blocked by contract", True, "Request failed, likely blocked by WAF")

def test_usage_endpoint():
    print("\n--- Testing /usage Endpoint ---")
    try:
        response = requests.get(f"{BASE_URL}/usage", timeout=2)
        assert response.status_code == 200 and isinstance(response.json(), list) and len(response.json()) > 0
        print_test("Endpoint returns a valid, well-formed list", True, f"Found {len(response.json())} endpoints")
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
    test_pattern_blocking()
    
    print("\n--- Test Suite Finished ---")

if __name__ == "__main__":
    main()
