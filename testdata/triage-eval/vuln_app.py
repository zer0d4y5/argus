# Deliberately planted fixtures for the appsec triage eval.
# Every finding here is planted and labeled. DO NOT fix.
from flask import Flask, request
import sqlite3
import subprocess
import yaml

app = Flask(__name__)

@app.route('/search')
def search():
    # PLANT(TP): SQL injection via f-string formatting of user input directly into query execution (CWE-89)
    username = request.args.get('username')
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cur.execute(query)
    return str(cur.fetchall())

@app.route('/lookup')
def lookup():
    # PLANT(TP): Command injection via shell=True with concatenated user input (CWE-78)
    host = request.args.get('host')
    subprocess.check_output("nslookup " + host, shell=True)
    return "Done"

@app.route('/parse', methods=['POST'])
def parse():
    # PLANT(TP): Unsafe deserialization using yaml.load without a Loader on untrusted input (CWE-502)
    data = request.data
    result = yaml.load(data)
    return str(result)

BASE_DIR = "/var/www/uploads"

@app.route('/download')
def download():
    # PLANT(TP): Path traversal — user-controlled filename into open() with no containment (CWE-22)
    import os
    filename = request.args.get('name')
    with open(os.path.join(BASE_DIR, filename)) as fh:
        return fh.read()

if __name__ == '__main__':
    app.run(debug=True)
