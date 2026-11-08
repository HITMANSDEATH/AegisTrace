import subprocess

def check():
    sql = """
import sqlite3
c = sqlite3.connect('/data/audit.db')
total = c.execute('SELECT count(id) FROM audit_log').fetchone()[0]
exp = c.execute("SELECT count(id) FROM audit_log WHERE session_id LIKE 'exp-%'").fetchone()[0]
print(f"Total rows: {total}, Exp rows: {exp}")
"""
    res = subprocess.run(
        ["docker", "exec", "-i", "aegistrace-audit_service-1", "python", "-"],
        input=sql,
        text=True,
        capture_output=True,
        check=True
    )
    print(res.stdout.strip())

if __name__ == "__main__":
    check()
