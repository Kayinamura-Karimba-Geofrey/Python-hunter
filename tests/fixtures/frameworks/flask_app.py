"""Flask Application Test Fixture."""

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.secret_key = "super_secret_hardcoded_key"

@app.route("/vulnerable", methods=["GET"])
def vulnerable_route():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "OK"

@app.route("/template", methods=["POST"])
def template_route():
    user_name = request.form.get("name")
    return render_template_string(f"Hello {user_name}")

if __name__ == "__main__":
    app.run(debug=True)
