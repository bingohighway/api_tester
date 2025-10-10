# WAF & API Gateway Testing Suite

This project provides a comprehensive suite of tools designed to test the functionality, security contract enforcement, and performance of Web Application Firewalls (WAFs) and API Gateways. It includes a versatile Python Flask API to act as a backend target, a functional tester, and a detailed performance analysis tool with a live dashboard.

This suite was generated on Friday, 10 October 2025.

## Features

**Test API Server (`api.py`)**
- A versatile Flask API with multiple endpoints for testing different scenarios.
- A human-readable `/usage` endpoint that describes all available capabilities.
- Endpoints to test timeouts (`/delay`), response codes (`/response-code`), and header reflection (`/headers`).
- Endpoints specifically designed to test security contract enforcement against an API specification.
- Serves its own OpenAPI contract at `/contract`.

**Performance Tester (`perf_tester.py`)**
- Measures detailed connection metrics: DNS, TCP, TLS Handshake, Time to First Byte (TTFB), and Total Time.
- Renders a live, full-history ASCII line graph in the terminal for each endpoint.
- Each graph is automatically scaled to the terminal width and the endpoint's specific performance range.
- Includes a cycling log of the 3 most recent requests below each graph.
- Saves all raw results to a uniquely named CSV file for later analysis, including a snippet of the response body.

**Functional Tester (`tester.py`)**
- A simple, fast script to quickly verify that the main API endpoints are online and functioning as expected.

## File Structure
```
.
├── api.py                  # The Flask test API server
├── tester.py               # The simple functional test script
├── perf_tester.py          # The advanced performance testing tool
├── setup_api.sh            # Setup script for the API server
├── setup_testers.sh        # Setup script for the test tools
└── README.md               # This documentation file
```

## Requirements

- Python 3.x
- `pip` and `venv` (usually included with Python)
- `curl` command-line tool
- A Zsh-compatible shell (the scripts are written in `zsh` but should work in `bash`)

## Setup

Follow these steps in your project directory to set up the necessary Python environments.

1.  **Make the setup scripts executable:**
```zsh
chmod +x setup_api.sh setup_testers.sh
```
2.  **Set up the API server environment:**
```zsh
./setup_api.sh
```
3.  **Set up the testers' environment:**
```zsh
./setup_testers.sh
```

## Usage

You will need at least two separate terminal windows/tabs to run the suite.

### 1. Run the API Server

In your first terminal, activate the API environment and start the server using Gunicorn.
```zsh
# Activate the environment
source api_env/bin/activate

# Run the server on port 5000 with 4 workers
gunicorn --bind 0.0.0.0:5000 --workers 4 api:app
```
The API is now running and ready to receive requests.

### 2. Run the Testers

In your second terminal, activate the testers' environment. You can then run either the functional or the performance tester.
```zsh
# Activate the environment
source tester_env/bin/activate
```
**Running the Functional Tester:**
This performs a quick check on the key endpoints.
```zsh
python3 tester.py
```
**Running the Performance Tester:**
This runs a detailed performance analysis with a live dashboard.
```zsh
# Run with default settings (50 runs per endpoint, 100ms delay)
python3 perf_tester.py

# Run a shorter test with a longer delay
python3 perf_tester.py --runs 20 --delay 250
```
**Performance Tester Options:**
- `--base-url`: The target URL for the API (defaults to `http://127.0.0.1:5000`).
- `--runs`: The number of requests to make **per endpoint**.
- `--delay`: The delay in milliseconds between each request.

## API Endpoint Details (`api.py`)

The test API provides the following endpoints, which you can view in a summarized format by visiting `http://127.0.0.1:5000/usage`.

| Endpoint                 | Method | Description                                                        | Contract Limits                                        |
| ------------------------ | ------ | ------------------------------------------------------------------ | ------------------------------------------------------ |
| `/usage`                 | GET    | Provides a human-readable summary of all endpoints.                | N/A                                                    |
| `/capabilities`          | GET    | Describes all available endpoints in OpenAPI format.               | N/A                                                    |
| `/delay/{milliseconds}`  | GET    | Delays the response by a specified time.                           | Max value: 60000, Min value: 0                         |
| `/headers`               | GET    | Reflects request headers.                                          | N/A                                                    |
| `/response-code/{code}`  | GET    | Returns a specific HTTP response code.                             | Max value: 599, Min value: 100                         |
| `/tight-echo`            | POST   | Echos a string with a very strict contract.                        | Max length: 50, alphabetic chars only                  |
| `/loose-echo`            | POST   | Echos a string with a looser contract.                             | Max length: 50, alphanumeric chars only                |
| `/random`                | GET    | Returns a random string with a strict contract length.             | Max value: 50                                          |
| `/contract`              | GET    | Returns the full OpenAPI contract for this API.                    | N/A                                                    |
| `/chars-contract`        | POST   | Accepts specific, 'suspicious' character strings enforced by contract. | must be one of: `["!'=", "''#"]`                       |
| `/chars-no-contract`     | POST   | Accepts specific, 'suspicious' character strings not enforced by contract. | N/A                                                    |

