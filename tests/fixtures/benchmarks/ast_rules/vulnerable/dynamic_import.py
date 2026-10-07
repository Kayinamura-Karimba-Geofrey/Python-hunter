# expect: PYH-AST-008
import importlib


def load_plugin(name: str) -> object:
    return importlib.import_module(name)
