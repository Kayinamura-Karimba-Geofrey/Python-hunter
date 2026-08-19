"""Metaclass & Monkey Patch fixture."""

class Meta(type):
    def __new__(cls, name, bases, dct):
        return super().__new__(cls, name, bases, dct)

class Base(metaclass=Meta):
    pass

def replacement_fn():
    return "hacked"

import os
os.system = replacement_fn
Base.target_method = replacement_fn
DynamicClass = type("DynamicClass", (object,), {})
