# Web Application Security Assessment – DVWA Authentication Module

## Executive Summary

A targeted grey-box security assessment was conducted against the authentication functionality of the Damn Vulnerable Web Application (DVWA) at `/vulnerabilities/brute/`. The objective was to evaluate the resilience of the login mechanism against automated credential-guessing attacks and identify weaknesses in how authentication data is transmitted, processed, and stored across DVWA's four security configurations (`Low`, `Medium`, `High`, and `Impossible`).

Testing identified **four security findings** across application logic, request handling, password storage, and transport security:

1. **High – Insufficient Authentication Controls Allow Automated Credential Brute-Force (`VULN-01`):** Despite introducing fixed delays at the `Medium` level and rotating anti-CSRF tokens with randomised delays at the `High` level, the application lacks effective failed-login tracking and account lockout controls at these levels. Using a Burp Suite session macro to retrieve refreshed CSRF tokens, automated password guessing successfully recovered the `admin` account password.

2. **Low – Authentication Credentials Exposed Through HTTP GET Query Parameters (`VULN-02`):** Across the `Low`, `Medium`, and `High` levels, login credentials are submitted via HTTP `GET` query strings. This causes plaintext usernames and passwords to appear in browser history and exposes them through subsequent HTTP `Referer` headers.

3. **Low – Weak Password Storage Using Unsalted MD5 Hashing (`VULN-03`):** Static source code analysis revealed that passwords are processed using unsalted `md5()` hashing across all four security levels, including `Impossible`. If database records are exposed, the use of a fast, unsalted hash makes stored password hashes susceptible to offline dictionary and brute-force attacks.

4. **Low – Cleartext Transmission of Sensitive Information Over HTTP (`VULN-04`):** Network traffic inspection confirmed that the application serves authentication pages and transmits credentials and `PHPSESSID` session cookies over unencrypted HTTP across all security configurations. Inspection also confirmed that the session cookie is issued without the `Secure` attribute.

While the `Impossible` configuration introduces controls that mitigate the demonstrated automated brute-force attack (`VULN-01`) and addresses the GET parameter exposure identified in (`VULN-02`), weaknesses in password storage (`VULN-03`) and transport security (`VULN-04`) remain present across all four configurations.

These findings highlight the importance of implementing layered authentication controls, secure password storage, and HTTPS enforcement before deploying an application in a production environment.

---

## Scope

The assessment was restricted to the configured authentication module of the DVWA lab environment. Other DVWA vulnerability modules were not configured in the test environment and were excluded from testing.

### In Scope

| Target Component | Details |
| :--- | :--- |
| **Application Endpoint** | `/vulnerabilities/brute/` |
| **Security Configurations** | `Low`, `Medium`, `High`, and `Impossible` |
| **Source Code Files** | `vulnerabilities/brute/source/{low,medium,high,impossible}.php` |
| **Assessment Focus** | Authentication rate limiting, account lockout mechanisms, anti-CSRF token handling, credential transport security, and password storage |

### Out of Scope

- All other DVWA modules (e.g., SQL Injection, Command Injection, Cross-Site Scripting, File Inclusion, and CSRF modules).
- Underlying host operating system, web server daemon configuration, and database service hardening.
- Volumetric network-layer Denial-of-Service (DoS) testing.

---

## Methodology

The engagement followed a structured **grey-box testing methodology** aligned with the **OWASP Web Security Testing Guide (WSTG)**, combining dynamic HTTP traffic analysis with static source code review.

### 1. Reconnaissance and Traffic Analysis

- Mapped the authentication workflow across all four DVWA security levels (`security=low`, `medium`, `high`, and `impossible`).
- Inspected HTTP requests, response headers, session cookies (`PHPSESSID`, `security`), and hidden form parameters (`user_token`) using Burp Suite Proxy.

### 2. Dynamic Authentication Testing

- Evaluated the effectiveness of server-side throttling, response delays, and anti-CSRF token validation against automated credential-guessing attacks.
- Configured Burp Suite Intruder with a session handling rule and recursive grep macro to dynamically extract single-use `user_token` values on the `High` security level.
- Analysed browser URL persistence, subsequent HTTP `Referer` headers, and `Set-Cookie` attributes to verify credential and session exposure paths.

### 3. Static Source Code Review

- Reviewed the server-side PHP implementations (`low.php`, `medium.php`, `high.php`, and `impossible.php`) to confirm the root causes of observed behaviour, inspect password hashing routines, and evaluate how defensive controls were implemented in the `Impossible` configuration.

### 4. Risk Classification and Remediation Reporting

- Classified each confirmed issue by severity based on exploitability, prerequisite conditions, and potential business impact.
- Mapped findings to relevant Common Weakness Enumeration (CWE) identifiers and documented actionable, code-level remediation recommendations.

---

## Summary of Findings

| ID | Finding Title | Severity | CWE | Affected Levels |
| :--- | :--- | :--- | :--- | :--- |
| [VULN-01](findings/01-brute-force.md) | Insufficient Authentication Controls Allow Automated Credential Brute-Force | **High** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Low, Medium, High |
| [VULN-02](findings/02-credential-exposure-get.md) | Authentication Credentials Exposed Through HTTP GET Query Parameters | **Low** | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Low, Medium, High |
| [VULN-03](findings/03-weak-password-hashing-md5.md) | Weak Password Storage Using Unsalted MD5 Hashing | **Low** | [CWE-916](https://cwe.mitre.org/data/definitions/916.html), [CWE-759](https://cwe.mitre.org/data/definitions/759.html) | Low, Medium, High, Impossible |
| [VULN-04](findings/04-cleartext-transmission-http.md) | Cleartext Transmission of Sensitive Information Over HTTP | **Low** | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Low, Medium, High, Impossible |

---

## Repository Structure

```text
dvwa-security-assessment/
├── README.md                                  # Executive summary, scope, methodology, and findings overview
├── findings/
│   ├── 01-brute-force.md                      # [VULN-01] Missing rate limiting and account lockout
│   ├── 02-credential-exposure-get.md          # [VULN-02] Plaintext credentials in HTTP GET query strings
│   ├── 03-weak-password-hashing-md5.md        # [VULN-03] Unsalted MD5 password hashing
│   └── 04-cleartext-transmission-http.md      # [VULN-04] Cleartext credential and session transmission
└── evidence/
    ├── VULN-01/                               # Sanitised screenshots for VULN-01
    ├── VULN-02/                               # Sanitised screenshots for VULN-02
    ├── VULN-03/                               # Supporting evidence for VULN-03 (optional)
    └── VULN-04/                               # Sanitised screenshots for VULN-04
```

## Evidence

Screenshots and supporting evidence are organised by finding under the `evidence/` directory. Evidence is referenced within the relevant finding reports to support the identified vulnerabilities and demonstrate the testing performed.

All published evidence should be sanitised to remove sensitive information, including session identifiers, authentication tokens, and passwords.
