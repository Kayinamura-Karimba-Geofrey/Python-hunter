# expect: none
import ast


def parse_literal(text: str) -> object:
    return ast.literal_eval(text)
