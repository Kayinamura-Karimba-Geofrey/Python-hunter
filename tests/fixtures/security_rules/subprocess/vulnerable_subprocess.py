import subprocess

def run_dangerous(cmd):
    subprocess.run(cmd, shell=True)
