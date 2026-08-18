"""Eval and Exec Test Fixture."""

import ast

eval("1 + 1")
code = "print('hello')"
exec(code)
safe_val = ast.literal_eval("{'a': 1}")
