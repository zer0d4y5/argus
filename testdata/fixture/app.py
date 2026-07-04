# Deliberately vulnerable sample used by the appsec smoke tests.
# Every issue in this file is planted on purpose. DO NOT fix.
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # PLANT: SQL injection via string formatting (CWE-89)
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # PLANT: command injection via shell=True (CWE-78)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/load", methods=["POST"])
def load():
    # PLANT: unsafe YAML deserialization (CWE-502)
    data = yaml.load(request.data)
    return str(data)


if __name__ == "__main__":
    # PLANT: debug mode enabled in production entrypoint
    app.run(host="0.0.0.0", debug=True)
