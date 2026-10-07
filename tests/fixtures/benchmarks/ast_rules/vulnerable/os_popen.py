# expect: PYH-AST-010
import os


def list_dir(path: str) -> str:
    return os.popen("ls " + path).read()
