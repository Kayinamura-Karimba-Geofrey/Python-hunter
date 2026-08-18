"""Pickle and YAML Test Fixture."""

import pickle
import yaml

data = b"cos\nsystem\n(S'ls'\ntR."
obj = pickle.loads(data)
yaml_data = "a: 1"
loaded = yaml.load(yaml_data)
safe_loaded = yaml.load(yaml_data, Loader=yaml.SafeLoader)

class CustomObj:
    def __reduce__(self):
        return (print, ("hello",))
