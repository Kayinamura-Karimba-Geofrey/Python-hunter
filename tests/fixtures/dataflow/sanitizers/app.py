"""Sanitizers and Context Fixture."""

from flask import request
import shlex
import html
import os

def safe_shell():
    val = request.args.get("cmd")
    safe_val = shlex.quote(val)
    os.system("ls " + safe_val)

def misapplied_sanitizer():
    val = request.args.get("cmd")
    escaped_html = html.escape(val)
    os.system("ls " + escaped_html)
