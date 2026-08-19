"""Dynamic imports test fixture."""

import importlib

def test_imports(user_mod):
    m1 = importlib.import_module("json")
    m2 = importlib.import_module(user_mod)
    m3 = __import__("sys")
    return m1, m2, m3
