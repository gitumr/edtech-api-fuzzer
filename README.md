# ⚡ EdTech API Fuzzer

> **Educational Module** · BCA/BSc Cyber Security & Ethical Hacking  
> _Automated Pentesting for EdTech API Ecosystems_

---

## ⚠️ Ethical Use Notice

> This tool is for **educational and authorized pentesting only**.  
> Only use it against systems you **own** or have **explicit written permission** to test.  
> Unauthorized use against live systems is **illegal** and **unethical**.

---

## 📂 Project Structure

```
api-fuzzer/
├── api_fuzzer.py      ← Main fuzzer script (run this)
├── payloads.py        ← Categorized payload library
├── demo_api.py        ← Intentionally vulnerable demo API (for practice)
├── requirements.txt   ← Python dependencies
└── results.csv        ← Auto-generated fuzzing results
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Demo API (Terminal 1)

```bash
python3 demo_api.py
```

You should see:
```
════════════════════════════════════════════════════════════
  ⚡  EdTech Demo API — Vulnerable by Design
  🎓  Use only for authorized pentesting practice
════════════════════════════════════════════════════════════
```

### 3. Run the Fuzzer (Terminal 2)

```bash
# Fuzz with all payloads (default)
python api_fuzzer.py

# Fuzz with only SQL Injection payloads
python api_fuzzer.py --category sql_injection

# Fuzz with XSS payloads
python api_fuzzer.py --category xss

# See all categories
python api_fuzzer.py --list-categories
```

---

## 🎯 What is Fuzz Testing?

**Fuzz Testing (Fuzzing)** is a software testing technique where you send **unexpected, malformed, or random inputs** to a program to discover bugs, crashes, and security vulnerabilities.

In API fuzzing, we send these bad inputs to API endpoints and observe:
- Does the server crash? (`500 Internal Server Error`)
- Does it leak sensitive data?
- Does it accept inputs it shouldn't (SQL injection, XSS)?
- Does it timeout unexpectedly?

---

## 📦 Payload Categories

| Category           | Description                                         | Count |
|--------------------|-----------------------------------------------------|-------|
| `strings`          | Long strings, empty, whitespace, unicode, null chars | 15    |
| `sql_injection`    | Classic SQLi, UNION, blind, time-based, error-based  | 10    |
| `xss`              | Script tags, img onerror, encoded variants           | 10    |
| `command_injection`| Shell metacharacters, subshells, OS commands         | 8     |
| `path_traversal`   | `../` sequences, encoded variants                    | 6     |
| `numeric`          | Overflow, NaN, Inf, negative, scientific notation    | 11    |
| `type_confusion`   | Booleans, null, lists, dicts, type coercion          | 10    |
| `auth_bypass`      | Empty tokens, JWT none algo, common admin strings    | 7     |
| `edtech`           | EdTech-specific: grade overflow, student ID tricks   | 11    |
| `all`              | Everything combined                                  | 88    |

---

## 🏴 Vulnerable Endpoints in Demo API

| Endpoint                      | Method | Vulnerability                        |
|-------------------------------|--------|--------------------------------------|
| `/api/students`               | POST   | No input validation, missing fields → 500 |
| `/api/students/search?name=`  | GET    | **SQL Injection** (raw string concat) |
| `/api/login`                  | POST   | Auth bypass (any username works)      |
| `/api/admin/users`            | GET    | **No authentication** (IDOR)          |

---

## 📊 Understanding Results (`results.csv`)

| Column             | Meaning                                     |
|--------------------|---------------------------------------------|
| `endpoint`         | Which API route was tested                  |
| `category`         | Payload category used                       |
| `label`            | Human-readable name of the payload          |
| `payload`          | The actual value sent                       |
| `status_code`      | HTTP response code (500 = crash!)           |
| `response_time_s`  | How long the request took                   |
| `response_snippet` | First 120 chars of the API response         |
| `interesting`      | `YES ⚠` if the result looks suspicious     |

### 🔍 What to Look For

- **Status 500**: Server crashed — possible unhandled exception
- **Status 200 on SQLi/Auth payloads**: Possible injection/bypass success
- **Keywords in response**: `secret`, `password`, `traceback`, `sqlite` → data leak
- **TIMEOUT**: Server may be vulnerable to slowdown attacks

---

## 🛡️ Key Learning Objectives

1. **Understand Fuzz Testing** — Why random/bad inputs matter
2. **Identify Input Validation Flaws** — What happens without validation
3. **Discover SQL Injection** — How unsanitized queries are exploited
4. **Recognize XSS Vectors** — How scripts get injected
5. **Find Authentication Issues** — Broken auth and IDOR
6. **Practice Responsible Disclosure** — How to report findings ethically

---

## 🔧 CLI Options

```
usage: api_fuzzer.py [-h] [--url URL] [--category CATEGORY]
                     [--timeout TIMEOUT] [--delay DELAY]
                     [--output OUTPUT] [--list-categories]

Options:
  --url URL              Base URL of the target API (default: http://127.0.0.1:5050)
  --category CATEGORY    Payload category to use (default: all)
  --timeout TIMEOUT      Request timeout in seconds (default: 8)
  --delay DELAY          Delay between requests in seconds (default: 0.3)
  --output OUTPUT        CSV output filename (default: results.csv)
  --list-categories      List all available payload categories and exit
```

---

## 📚 Further Reading

- [OWASP Top 10 API Security Risks](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide — Fuzzing](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
