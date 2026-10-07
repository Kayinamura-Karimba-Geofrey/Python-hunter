# expect: PYH-AST-004
import os


def ping(host: str) -> int:
    return os.system("ping -c 1 " + host)
