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
