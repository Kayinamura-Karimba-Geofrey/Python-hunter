"""Eval / Exec test fixture."""

import ast

def test_eval(code_str):
    c1 = eval("1 + 1")
    c2 = eval(code_str)
    c3 = exec(code_str)
    c4 = ast.literal_eval("[1, 2, 3]")
    code_obj = compile(code_str, "<string>", "exec")
    exec(code_obj)
    return c1, c2, c3, c4
