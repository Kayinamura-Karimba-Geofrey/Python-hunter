"""Knowledge Graph test fixture."""

import os
import subprocess

def public_api_handler(user_input: str):
    clean_input = user_input
    execute_query(clean_input)

def execute_query(query: str):
    subprocess.call(["sh", "-c", query])
