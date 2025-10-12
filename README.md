# WAF & API Gateway Testing Suite

(An introductory section explaining the project philosophy would be here)

## WAF Efficacy Fuzzer (`fuzzer.py`) Details

The fuzzer is the most powerful tool in this suite for evaluating WAF rules. It tests payloads against two endpoints to distinguish between signature detection and contract enforcement.

### Baseline Server Protection (Gunicorn)

An important concept in this test suite is establishing a baseline. The Gunicorn server running the API provides a minimal level of protection and may drop connections for highly suspicious requests (like deserialization patterns) before the API code is even reached. The table below indicates which payloads are likely to be blocked by this baseline protection, which helps you interpret your results before a WAF is in place.

### SQL Injection (SQLi) Payloads

| Payload                                                | Technique / Description                                            | Expected Baseline Block (Gunicorn) |
| ------------------------------------------------------ | ------------------------------------------------------------------ | ---------------------------------- |
| `' OR 1=1--`                                           | Classic Tautology to bypass logic.                                 | No                                 |
| `UNION SELECT user, password FROM users`               | UNION Attack to extract data from other tables.                    | No                                 |
| `'; DROP TABLE members;--`                              | Stacked Query to execute a second, destructive command.            | No                                 |
| `OR IF(1=1, SLEEP(5), 0)`                               | Time-based Blind to infer data by measuring response time.         | No                                 |
| ... *(and so on for all SQLi payloads)* | ...                                                                | ...                                |

### Cross-Site Scripting (XSS) Payloads

| Payload                                    | Technique / Description                                        | Expected Baseline Block (Gunicorn) |
| ------------------------------------------ | -------------------------------------------------------------- | ---------------------------------- |
| `<script>alert('XSS')</script>`            | Basic reflected XSS proof-of-concept.                          | No                                 |
| `<img src=x onerror=alert(document.cookie)>` | Event Handler Injection to bypass basic `<script>` filters.    | No                                 |
| ... *(and so on for all XSS payloads)* | ...                                                            | ...                                |

### Command Injection Payloads

| Payload                | Technique / Description                                 | Expected Baseline Block (Gunicorn) |
| ---------------------- | ------------------------------------------------------- | ---------------------------------- |
| `| whoami`               | Pipe Execution to run a new command.                    | No                                 |
| `; ls -la /`             | Semicolon Separator to stack commands.                  | No                                 |
| `id\ncat /etc/hosts`   | Newline Separator to stack commands in shell scripts.   | **Yes** |

### Log & Header Injection Payloads

| Type                | Payload                                                        | Technique / Description                                       | Expected Baseline Block (Gunicorn) |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------- |
| Log Injection       | `user=guest%0a%0dmalicious_log_entry`                          | CRLF Injection to forge log entries.                          | **Yes** |
| HTTP Header Inj     | `value%0d%0aContent-Length:%200...`                            | Response Splitting to inject new HTTP headers.                | **Yes** |

### Insecure Deserialization Payloads

| Type                | Payload                                                        | Technique / Description                                       | Expected Baseline Block (Gunicorn) |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------- |
| Deserialization (Java)| `JRMI`                                                         | Magic bytes for a Java RMI call, a common exploit vector.     | **Yes** |
| Deserialization (Python)| `cposix\nsystem\n`                                             | A basic Python Pickle payload attempting to call a system command. | **Yes** |
| Deserialization (.NET)| `AAEAAAD/////AQAAAAAAAAAMAgAAAFBTeXN0ZW0`                      | A common gadget chain for .NET deserialization exploits.       | **Yes** |

(The rest of the README with Setup, Usage, and other scenario details would follow)
