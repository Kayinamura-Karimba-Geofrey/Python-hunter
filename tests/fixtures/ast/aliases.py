import subprocess as sp
from os import system as sys_call

def run_cmd(cmd: str):
    sp.run(cmd)
    sys_call(cmd)
