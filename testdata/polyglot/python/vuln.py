# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import hashlib
import os
import sqlite3
import subprocess


def sql_injection(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # PLANT: SQL injection via string formatting (CWE-89)
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cur.fetchall()


def command_injection(host):
    # PLANT: OS command injection via shell=True with concatenation (CWE-78)
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def weak_hash(password):
    # PLANT: weak hash (MD5) over a password (CWE-328)
    return hashlib.md5(password.encode()).hexdigest()


def path_traversal(filename):
    # PLANT: path traversal via unsanitized user filename (CWE-22)
    with open(os.path.join("/var/data", filename)) as fh:
        return fh.read()
