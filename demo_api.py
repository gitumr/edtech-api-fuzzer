"""
demo_api.py — Intentionally Vulnerable EdTech Demo API
EdTech API Fuzzer | Ethical Hacking Educational Module

⚠️  WARNING: This API is INTENTIONALLY VULNERABLE.
    It is designed for educational/pentesting practice ONLY.
    NEVER deploy this in production.

Simulates a student management system with multiple vulnerabilities:
  - Missing input validation (buffer-like overflow, crashes)
  - SQL-injectable endpoints (uses in-memory SQLite)
  - Improper error handling (leaks stack traces)
  - Missing authentication on admin routes
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import logging

app = Flask(__name__)

# Suppress Flask's default banner for clean output
log = logging.getLogger("werkzeug")
log.setLevel(logging.WARNING)

DB_PATH = ":memory:"  # In-memory SQLite – resets on each run

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn

# Module-level connection (in-memory, shared)
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    cursor = _conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS students (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            email    TEXT NOT NULL,
            grade    REAL,
            course   TEXT
        );
        CREATE TABLE IF NOT EXISTS admin_secrets (
            id       INTEGER PRIMARY KEY,
            secret   TEXT
        );
        INSERT INTO admin_secrets (id, secret) VALUES (1, 'SUPER_SECRET_DB_PASSWORD_12345');
        INSERT INTO students (name, email, grade, course)
            VALUES ('Alice Johnson', 'alice@university.edu', 89.5, 'CS101');
        INSERT INTO students (name, email, grade, course)
            VALUES ('Bob Smith', 'bob@university.edu', 75.0, 'MATH202');
    """)
    _conn.commit()

init_db()

# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────
def banner():
    print("\n" + "═" * 60)
    print("  ⚡  EdTech Demo API — Vulnerable by Design")
    print("  🎓  Use only for authorized pentesting practice")
    print("═" * 60)
    print("  Endpoints:")
    print("    GET  /api/students          — List all students")
    print("    POST /api/students          — Add a student (vulnerable)")
    print("    GET  /api/students/search   — Search by name (SQLi!)")
    print("    GET  /api/courses           — List courses")
    print("    POST /api/login             — Login (auth bypass!)")
    print("    GET  /api/admin/users       — No auth required (IDOR!)")
    print("═" * 60 + "\n")

# ─────────────────────────────────────────────
# ROUTE: GET /api/students
# ─────────────────────────────────────────────
@app.route("/api/students", methods=["GET"])
def get_students():
    cursor = _conn.cursor()
    cursor.execute("SELECT id, name, email, grade, course FROM students")
    rows = cursor.fetchall()
    students = [
        {"id": r[0], "name": r[1], "email": r[2], "grade": r[3], "course": r[4]}
        for r in rows
    ]
    return jsonify({"status": "success", "count": len(students), "students": students})

# ─────────────────────────────────────────────
# ROUTE: POST /api/students  — VULNERABLE: No input validation
# ─────────────────────────────────────────────
@app.route("/api/students", methods=["POST"])
def add_student():
    data = request.get_json()

    # ⚠️ VULNERABILITY 1: No validation on length → app will choke on very long strings
    # ⚠️ VULNERABILITY 2: None/missing fields cause unhandled exceptions → 500 leaks
    name   = data["name"]    # KeyError if missing
    email  = data["email"]   # KeyError if missing
    grade  = data.get("grade", 0)
    course = data.get("course", "UNKNOWN")

    # ⚠️ VULNERABILITY 3: Grade accepts any numeric value, even negative/overflow
    cursor = _conn.cursor()
    cursor.execute(
        "INSERT INTO students (name, email, grade, course) VALUES (?, ?, ?, ?)",
        (name, email, grade, course)
    )
    _conn.commit()

    return jsonify({
        "status":  "created",
        "message": f"Student '{name}' enrolled successfully.",
        "id":      cursor.lastrowid
    }), 201

# ─────────────────────────────────────────────
# ROUTE: GET /api/students/search — VULNERABLE: SQL Injection
# ─────────────────────────────────────────────
@app.route("/api/students/search", methods=["GET"])
def search_students():
    name = request.args.get("name", "")

    # ⚠️ VULNERABILITY 4: Raw string concatenation → SQL Injection
    query = f"SELECT id, name, email, grade, course FROM students WHERE name LIKE '%{name}%'"

    try:
        cursor = _conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        students = [
            {"id": r[0], "name": r[1], "email": r[2], "grade": r[3], "course": r[4]}
            for r in rows
        ]
        return jsonify({"status": "success", "results": students})
    except Exception as e:
        # ⚠️ VULNERABILITY 5: Full error message exposed (stack trace leak)
        return jsonify({"status": "error", "detail": str(e)}), 500

# ─────────────────────────────────────────────
# ROUTE: GET /api/courses
# ─────────────────────────────────────────────
@app.route("/api/courses", methods=["GET"])
def get_courses():
    courses = [
        {"id": "CS101",   "name": "Introduction to Computer Science", "credits": 3},
        {"id": "MATH202", "name": "Calculus II",                       "credits": 4},
        {"id": "PHY301",  "name": "Physics for Engineers",             "credits": 4},
        {"id": "ENG101",  "name": "English Composition",               "credits": 3},
    ]
    return jsonify({"status": "success", "courses": courses})

# ─────────────────────────────────────────────
# ROUTE: POST /api/login — VULNERABLE: Auth Bypass
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # ⚠️ VULNERABILITY 6: Hardcoded credentials with no rate-limiting
    # ⚠️ VULNERABILITY 7: Boolean logic flaw → any truthy username bypasses check
    if username == "admin" and password == "admin123":
        return jsonify({"status": "success", "token": "FAKE_JWT_TOKEN_ADMIN_12345", "role": "admin"})
    elif username:
        # Any non-empty username gets a "guest" token
        return jsonify({"status": "success", "token": "FAKE_JWT_TOKEN_GUEST", "role": "guest"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# ─────────────────────────────────────────────
# ROUTE: GET /api/admin/users — VULNERABLE: No Authentication (IDOR)
# ─────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    # ⚠️ VULNERABILITY 8: No token/auth check on admin route
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM students")
    rows = cursor.fetchall()
    cursor.execute("SELECT secret FROM admin_secrets")
    secrets = [r[0] for r in cursor.fetchall()]

    return jsonify({
        "status":  "success",
        "warning": "⚠️ This endpoint requires authentication — it's exposed!",
        "students": rows,
        "admin_secrets_exposed": secrets   # Sensitive data leak
    })

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    banner()
    app.run(host="127.0.0.1", port=5050, debug=False)
