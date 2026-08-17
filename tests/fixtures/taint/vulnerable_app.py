"""Synthetic vulnerable Python application for taint analysis testing."""

import os
import subprocess
import requests
from flask import request


def vulnerable_sql_route():
    username = request.args["username"]
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)


def vulnerable_cmd_route():
    cmd = request.args["command"]
    os.system(cmd)


def vulnerable_path_route():
    filename = request.args["filename"]
    f = open(filename, "r")
    content = f.read()
    return content


def vulnerable_ssrf_route():
    url = request.args["url"]
    resp = requests.get(url)
    return resp.text


def vulnerable_code_route():
    expr = request.args["expr"]
    result = eval(expr)
    return str(result)


def safe_parameterized_sql():
    username = request.args["username"]
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))


def safe_command_list():
    filename = request.args["filename"]
    subprocess.run(["ls", filename], shell=False)


def safe_sanitized_path():
    filename = request.args["filename"]
    safe_name = os.path.basename(filename)
    open(safe_name, "r")
