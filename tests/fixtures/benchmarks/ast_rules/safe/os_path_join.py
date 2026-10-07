# expect: none
import os


def home() -> str:
    return os.path.join(os.sep, "home")
