# expect: PYH-AST-006
import pickle


def load_session(blob: bytes) -> object:
    return pickle.loads(blob)
