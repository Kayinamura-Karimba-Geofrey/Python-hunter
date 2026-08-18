"""Interprocedural Dataflow Fixture."""

from flask import request
import os

def process_query(q):
    return "SELECT * FROM users WHERE name = " + q

def execute_db(sql):
    os.system(sql)

def handle_request():
    val = request.args.get("name")
    sql = process_query(val)
    execute_db(sql)
