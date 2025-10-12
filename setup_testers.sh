#!/bin/zsh
echo "--- Setting up Python environment for the API Testers ---"
if ! command -v python3 &> /dev/null; then echo "Error: python3 is not installed."; exit 1; fi
python3 -m venv tester_env; source tester_env/bin/activate
echo "--- Installing Requests library ---"; pip install requests
echo "\n--- Setup Complete ---"
echo "To run the functional tester:"; echo "source tester_env/bin/activate"; echo "python3 tester.py"
echo "\nTo run the WAF fuzzer:"; echo "source tester_env/bin/activate"; echo "python3 fuzzer.py"
echo "\nTo run the performance tester:"; echo "source tester_env/bin/activate"; echo "python3 perf_tester.py"
