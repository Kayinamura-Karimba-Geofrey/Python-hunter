# expect: none
import json


def load_session(blob: str) -> object:
    return json.loads(blob)
