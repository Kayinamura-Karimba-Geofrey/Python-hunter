# expect: PYH-AST-007
import yaml


def parse(document: str) -> object:
    return yaml.load(document)
