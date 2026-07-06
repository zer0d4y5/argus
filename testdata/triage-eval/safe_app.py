# Deliberately planted fixtures for the appsec triage eval.
# Every finding here is planted and labeled. DO NOT fix.
from flask import Flask, request
import sqlite3
import subprocess
import yaml

app = Flask(__name__)

@app.route('/safe_search')
def safe_search():
    # PLANT(FP): SQL with user input but properly parameterized using placeholders (CWE-89 mitigated)
    username = request.args.get('username')
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = ?"
    cur.execute(query, (username,))
    return str(cur.fetchall())

@app.route('/safe_uptime')
def safe_uptime():
    # PLANT(FP): subprocess.check_output with shell=True but hardcoded constant string, no user input anywhere (CWE-78 mitigated)
    subprocess.check_output("uptime", shell=True)
    return "Done"

@app.route('/safe_parse', methods=['POST'])
def safe_parse():
    # PLANT(FP): yaml.safe_load used on untrusted input, preventing arbitrary code execution (CWE-502 mitigated)
    data = request.data
    result = yaml.safe_load(data)
    return str(result)

# PLANT(FP): hardcoded /tmp path, but a constant used read-only at startup (CWE-377 not exploitable here)
LOG_PATH = "/tmp/app.log"

if __name__ == '__main__':
    app.run(debug=True)
