import os
import subprocess as sp
from typing import Optional

def execute(cmd: str) -> Optional[int]:
    return sp.call(cmd)
