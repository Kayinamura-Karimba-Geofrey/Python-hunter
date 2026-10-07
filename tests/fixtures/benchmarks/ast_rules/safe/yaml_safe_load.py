# expect: none
import yaml


def parse(document: str) -> object:
    return yaml.safe_load(document)
