# expect: none
import subprocess


def list_files() -> str:
    return subprocess.run(["ls", "-l"], capture_output=True, text=True, check=True).stdout
