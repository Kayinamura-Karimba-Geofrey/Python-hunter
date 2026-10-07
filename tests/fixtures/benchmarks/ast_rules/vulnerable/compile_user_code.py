# expect: PYH-AST-003


def build(source: str) -> object:
    return compile(source, "<user>", "exec")
