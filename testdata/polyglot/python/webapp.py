# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import random
import string

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # PLANT(py-ssti, min-profile=standard, CWE-96): server-side template injection via string-built template
    return render_template_string("Hello " + name)


def session_token():
    # PLANT(py-weak-random, min-profile=max, CWE-330): predictable PRNG for a security token
    return "".join(random.choice(string.ascii_letters) for _ in range(32))


if __name__ == "__main__":
    # PLANT(py-flask-debug, min-profile=fast, CWE-489): debug server in production entrypoint
    app.run(debug=True)
