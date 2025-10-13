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
