"""
api_fuzzer.py — Professional EdTech API Fuzzer
EdTech API Fuzzer | Ethical Hacking Educational Module

IMPORTANT: Only use on systems you are authorized to test.
This tool is for educational and ethical pentesting purposes only.

Usage:
    # Fuzz against the local demo API:
    python api_fuzzer.py

    # Fuzz against a custom URL:
    python api_fuzzer.py --url http://your-api.com/endpoint --method POST

    # Use a specific payload category:
    python api_fuzzer.py --category sql_injection

    # Run all payload categories:
    python api_fuzzer.py --all
"""

import requests
import csv
import time
import json
import argparse
import sys
import os
from datetime import datetime
from payloads import (
    STRINGS, SQL_INJECTION, XSS, COMMAND_INJECTION,
    PATH_TRAVERSAL, NUMERIC, TYPE_CONFUSION, AUTH_BYPASS,
    EDTECH_SPECIFIC, ALL_PAYLOADS
)

# ─────────────────────────────────────────────
# ANSI Colors for terminal output
# ─────────────────────────────────────────────
class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"
    PURPLE = "\033[95m"

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DEFAULT_CONFIG = {
    "base_url":   "http://127.0.0.1:5050",
    "timeout":    8,
    "delay":      0.3,          # seconds between requests (be respectful)
    "output_csv": "results.csv",
}

# Response time thresholds (seconds)
TIME_FAST   = 0.5   # Below this  → green
TIME_SLOW   = 2.0   # Above this  → red and flagged as interesting

# Target endpoints with their methods and body field mappings
ENDPOINTS = [
    {
        "name":    "Add Student (POST)",
        "url":     "{base}/api/students",
        "method":  "POST",
        "fields":  ["name", "email", "grade", "course"],
        "fuzz_field": "name",       # which field gets fuzzed
    },
    {
        "name":    "Search Students (GET ?name=)",
        "url":     "{base}/api/students/search",
        "method":  "GET",
        "params":  {"name": "__FUZZ__"},
    },
    {
        "name":    "Login (POST)",
        "url":     "{base}/api/login",
        "method":  "POST",
        "fields":  ["username", "password"],
        "fuzz_field": "username",
    },
    {
        "name":    "Admin Users (GET) — No Auth",
        "url":     "{base}/api/admin/users",
        "method":  "GET",
    },
]

CATEGORIES = {
    "strings":          STRINGS,
    "sql_injection":    SQL_INJECTION,
    "xss":              XSS,
    "command_injection":COMMAND_INJECTION,
    "path_traversal":   PATH_TRAVERSAL,
    "numeric":          NUMERIC,
    "type_confusion":   TYPE_CONFUSION,
    "auth_bypass":      AUTH_BYPASS,
    "edtech":           EDTECH_SPECIFIC,
    "all":              ALL_PAYLOADS,
}

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
def print_banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          ⚡  EdTech API Fuzzer — Ethical Pentesting Tool     ║
║          🎓  For Educational Use Only — BCA/BSc Module       ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}
{Color.GRAY}  Author : EdTech Security Module
  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Target : {DEFAULT_CONFIG['base_url']}
{Color.RESET}""")

# ─────────────────────────────────────────────
# STATUS CODE INTERPRETATION
# ─────────────────────────────────────────────
def interpret_status(code) -> tuple[str, str]:
    """Returns (label, color) for a status code."""
    if code == "TIMEOUT":
        return "TIMEOUT ⏱", Color.YELLOW
    if code == "ERROR":
        return "NETWORK ERR ✗", Color.RED
    code = int(code)
    if code == 200:
        return "OK ✓", Color.GREEN
    elif code == 201:
        return "CREATED ✓", Color.GREEN
    elif code == 400:
        return "BAD INPUT ⚠", Color.YELLOW
    elif code == 401:
        return "UNAUTH ⚠", Color.YELLOW
    elif code == 403:
        return "FORBIDDEN", Color.YELLOW
    elif code == 404:
        return "NOT FOUND", Color.GRAY
    elif code == 422:
        return "UNPROCESSABLE ⚠", Color.YELLOW
    elif code == 500:
        return "SERVER ERROR 🔥", Color.RED
    elif code >= 500:
        return f"SERVER ERR {code} 🔥", Color.RED
    else:
        return str(code), Color.WHITE

def is_interesting(result: dict) -> bool:
    """Marks a result as 'interesting' from a security POV."""
    code = result.get("status_code")
    if code in ("ERROR", "TIMEOUT"):
        return True
    try:
        c = int(code)
        if c == 500:
            return True   # Server crash
        if c == 200 and result.get("category") in ("sql_injection", "auth_bypass"):
            return True   # Unexpected success on dangerous payload
    except (ValueError, TypeError):
        pass
    resp = result.get("response_snippet", "").lower()
    # Sensitive data in response
    for keyword in ["secret", "password", "token", "traceback", "exception", "sqlite"]:
        if keyword in resp:
            return True
    # Slow response — possible DoS / time-based injection
    try:
        if float(result.get("response_time_s", 0)) >= TIME_SLOW:
            return True
    except (ValueError, TypeError):
        pass
    return False


def format_time(elapsed) -> str:
    """Return a color-coded string for response time."""
    try:
        t = float(elapsed)
    except (ValueError, TypeError):
        return f"{Color.GRAY}N/A{Color.RESET}"
    if t < TIME_FAST:
        color = Color.GREEN
    elif t < TIME_SLOW:
        color = Color.YELLOW
    else:
        color = Color.RED
    return f"{color}{t:.3f}s{Color.RESET}"

# ─────────────────────────────────────────────
# CORE FUZZING FUNCTION
# ─────────────────────────────────────────────
def fuzz_endpoint(endpoint: dict, payloads: dict, category: str, base_url: str, timeout: int, delay: float) -> list[dict]:
    results = []
    url = endpoint["url"].format(base=base_url)
    method = endpoint["method"].upper()
    ep_name = endpoint["name"]

    print(f"\n{Color.BOLD}{Color.BLUE}┌─ Endpoint: {ep_name}{Color.RESET}")
    print(f"{Color.BLUE}│  Method : {method}  →  {url}{Color.RESET}")
    print(f"{Color.BLUE}└─ Payloads: {len(payloads)}{Color.RESET}\n")

    total = len(payloads)
    findings = 0

    for idx, (label, payload) in enumerate(payloads.items(), start=1):
        # Build request
        headers = {"Content-Type": "application/json"}
        params  = None
        body    = None

        if method == "POST":
            fuzz_field = endpoint.get("fuzz_field", "name")
            body = {
                "name":     "Test Student",
                "email":    "test@edtech.edu",
                "grade":    85,
                "course":   "CS101",
                "username": "student",
                "password": "pass123",
            }
            body[fuzz_field] = payload

        elif method == "GET" and "params" in endpoint:
            params = {k: (payload if v == "__FUZZ__" else v)
                      for k, v in endpoint["params"].items()}

        try:
            start = time.time()
            resp  = requests.request(
                method,
                url,
                json=body if method == "POST" else None,
                params=params,
                headers=headers,
                timeout=timeout
            )
            elapsed = round(time.time() - start, 3)
            code    = resp.status_code
            snippet = resp.text[:120].replace("\n", " ")

        except requests.exceptions.Timeout:
            elapsed = timeout
            code    = "TIMEOUT"
            snippet = "Request timed out"
        except requests.exceptions.ConnectionError:
            elapsed = 0
            code    = "ERROR"
            snippet = "Connection refused — is the demo API running?"
        except Exception as e:
            elapsed = 0
            code    = "ERROR"
            snippet = str(e)[:120]

        result = {
            "endpoint":         ep_name,
            "category":         category,
            "label":            label,
            "payload":          str(payload)[:80],
            "status_code":      code,
            "response_time_s":  elapsed,
            "response_snippet": snippet,
            "interesting":      "",
        }
        result["interesting"] = "YES ⚠" if is_interesting(result) else "no"
        if is_interesting(result):
            findings += 1

        results.append(result)

        # Pretty terminal print
        status_label, color = interpret_status(code)
        interesting_flag = f" {Color.RED}★ INTERESTING{Color.RESET}" if result["interesting"].startswith("YES") else ""
        print(
            f"  {Color.GRAY}[{idx:>3}/{total}]{Color.RESET} "
            f"{Color.PURPLE}{label:<30}{Color.RESET}  "
            f"{color}{status_label:<20}{Color.RESET}  "
            f"{format_time(elapsed)}"
            f"{interesting_flag}"
        )

        time.sleep(delay)

    print(f"\n  → Findings on this endpoint: {Color.YELLOW}{findings}{Color.RESET} interesting responses\n")
    return results

# ─────────────────────────────────────────────
# CSV WRITER
# ─────────────────────────────────────────────
def write_csv(results: list[dict], path: str):
    fieldnames = ["endpoint", "category", "label", "payload",
                  "status_code", "response_time_s", "response_snippet", "interesting"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

# ─────────────────────────────────────────────
# SUMMARY REPORT
# ─────────────────────────────────────────────
def print_summary(results: list[dict], output_path: str):
    total     = len(results)
    interesting = [r for r in results if r["interesting"].startswith("YES")]
    server_err  = [r for r in results if str(r["status_code"]) == "500"]
    timeouts    = [r for r in results if r["status_code"] in ("TIMEOUT", "ERROR")]

    # ── Timing stats (exclude error/timeout rows with non-numeric times) ──
    timed = []
    for r in results:
        try:
            timed.append((float(r["response_time_s"]), r))
        except (ValueError, TypeError):
            pass

    if timed:
        times      = [t for t, _ in timed]
        avg_time   = sum(times) / len(times)
        min_time   = min(times)
        max_time   = max(times)
        slowest    = sorted(timed, key=lambda x: x[0], reverse=True)[:5]
    else:
        avg_time = min_time = max_time = 0.0
        slowest = []

    print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    📊  Fuzzing Summary                       ║
╚══════════════════════════════════════════════════════════════╝{Color.RESET}

  {Color.WHITE}Total Requests Sent : {Color.BOLD}{total}{Color.RESET}
  {Color.RED}Interesting Findings: {Color.BOLD}{len(interesting)}{Color.RESET}
  {Color.RED}Server Errors (500) : {Color.BOLD}{len(server_err)}{Color.RESET}
  {Color.YELLOW}Timeouts / Errors   : {Color.BOLD}{len(timeouts)}{Color.RESET}
  {Color.GREEN}Results Saved To    : {Color.BOLD}{output_path}{Color.RESET}
""")

    # ── Response Time Report ──────────────────────────────────────────────
    print(f"  {Color.CYAN}{Color.BOLD}⏱  Response Time Statistics:{Color.RESET}")
    print(f"     Fastest : {format_time(min_time)}")
    print(f"     Average : {format_time(avg_time)}")
    print(f"     Slowest : {format_time(max_time)}")

    if slowest:
        print(f"\n  {Color.YELLOW}  Top 5 Slowest Requests:{Color.RESET}")
        for t, r in slowest:
            slow_flag = f"  {Color.RED}⚠ SLOW{Color.RESET}" if t >= TIME_SLOW else ""
            print(
                f"    {format_time(t)}  [{r['category']}] {r['label']:<28}"
                f"  Status: {r['status_code']}{slow_flag}"
            )

    # ── Interesting Findings ──────────────────────────────────────────────
    if interesting:
        print(f"\n  {Color.RED}{Color.BOLD}⚠  Top Interesting Findings:{Color.RESET}")
        for r in interesting[:10]:
            print(
                f"  {Color.YELLOW}→{Color.RESET} "
                f"[{r['category']}] {r['label']:<30} "
                f"Status: {r['status_code']}  "
                f"| {r['response_snippet'][:60]}..."
            )
    print()

# ─────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="EdTech API Fuzzer — Ethical Pentesting Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_fuzzer.py                          # Fuzz demo API (all payloads)
  python api_fuzzer.py --category sql_injection # Only SQLi payloads
  python api_fuzzer.py --category xss           # Only XSS payloads
  python api_fuzzer.py --url http://api.com     # Custom target URL
  python api_fuzzer.py --list-categories        # Show payload categories

Categories: strings, sql_injection, xss, command_injection,
            path_traversal, numeric, type_confusion, auth_bypass,
            edtech, all
        """
    )
    parser.add_argument("--url",        default=DEFAULT_CONFIG["base_url"],
                        help="Base URL of the target API")
    parser.add_argument("--category",   default="all",
                        help="Payload category to use (default: all)")
    parser.add_argument("--timeout",    type=int, default=DEFAULT_CONFIG["timeout"],
                        help="Request timeout in seconds (default: 8)")
    parser.add_argument("--delay",      type=float, default=DEFAULT_CONFIG["delay"],
                        help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output",     default=DEFAULT_CONFIG["output_csv"],
                        help="CSV output filename (default: results.csv)")
    parser.add_argument("--list-categories", action="store_true",
                        help="List all available payload categories and exit")
    return parser.parse_args()

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    args = parse_args()

    if args.list_categories:
        print(f"\n{Color.CYAN}Available Payload Categories:{Color.RESET}\n")
        for name, payloads in CATEGORIES.items():
            print(f"  {Color.BOLD}{name:<20}{Color.RESET} — {len(payloads)} payloads")
        print()
        sys.exit(0)

    print_banner()

    # Validate category
    if args.category not in CATEGORIES:
        print(f"{Color.RED}Error: Unknown category '{args.category}'.{Color.RESET}")
        print(f"  Run with --list-categories to see options.\n")
        sys.exit(1)

    chosen_payloads = CATEGORIES[args.category]

    print(f"  {Color.WHITE}Category  : {Color.BOLD}{args.category} ({len(chosen_payloads)} payloads){Color.RESET}")
    print(f"  {Color.WHITE}Target URL: {Color.BOLD}{args.url}{Color.RESET}")
    print(f"  {Color.WHITE}Timeout   : {Color.BOLD}{args.timeout}s{Color.RESET}")
    print(f"  {Color.WHITE}Delay     : {Color.BOLD}{args.delay}s between requests{Color.RESET}")
    print(f"\n  {Color.YELLOW}⚠  Ensure you have authorization to test this endpoint.{Color.RESET}\n")

    all_results = []

    for endpoint in ENDPOINTS:
        # Skip non-fuzzable GET-only endpoints (no params) during payload fuzzing
        if endpoint["method"] == "GET" and "params" not in endpoint:
            continue

        results = fuzz_endpoint(
            endpoint=endpoint,
            payloads=chosen_payloads,
            category=args.category,
            base_url=args.url,
            timeout=args.timeout,
            delay=args.delay,
        )
        all_results.extend(results)

    # Save results
    write_csv(all_results, args.output)
    print_summary(all_results, args.output)

if __name__ == "__main__":
    main()
