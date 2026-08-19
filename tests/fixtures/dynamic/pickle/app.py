"""Pickle & YAML test fixture."""

import pickle
import yaml
import marshal
import json

def test_pickle(data):
    obj1 = pickle.loads(data)
    obj2 = marshal.loads(data)
    obj3 = json.loads('{"key": "val"}')
    y1 = yaml.load(data, Loader=yaml.SafeLoader)
    y2 = yaml.unsafe_load(data)
    return obj1, obj2, obj3, y1, y2

class CustomPayload:
    def __reduce__(self):
        return (eval, ("import os; os.system('id')",))
