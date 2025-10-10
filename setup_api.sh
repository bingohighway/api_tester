#!/bin/zsh
echo "--- Setting up Python environment for the Test API ---"
if ! command -v python3 &> /dev/null; then echo "Error: python3 is not installed."; exit 1; fi
python3 -m venv api_env; source api_env/bin/activate
echo "--- Installing Flask and Gunicorn ---"; pip install Flask gunicorn
echo "\n--- Setup Complete ---"
echo "To run the API server, activate the environment and use Gunicorn:"
echo "source api_env/bin/activate"
echo "gunicorn --bind 0.0.0.0:5000 --workers 4 api:app"
