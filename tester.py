import requests, time, json
from urllib.parse import quote

BASE_URL = "http://127.0.0.1:5000"
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
    test_response_codes()
    test_contract_security()
    test_pattern_blocking()
    test_encoded_bypass_attempt()
    
    print("\n--- Test Suite Finished ---")

if __name__ == "__main__":
    main()
