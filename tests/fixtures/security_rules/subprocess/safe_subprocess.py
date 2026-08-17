import subprocess

def run_safe():
    subprocess.run(["ls", "-la"], shell=False)
