"""Dynamic Import Test Fixture."""

import importlib

json_mod = importlib.import_module("json")
mod_name = "sys"
dyn_mod = importlib.import_module(mod_name)
old_imp = __import__("math")
