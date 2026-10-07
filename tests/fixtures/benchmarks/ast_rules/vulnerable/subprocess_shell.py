# expect: PYH-AST-005
import subprocess


def archive(name: str) -> None:
    subprocess.run(f"tar czf {name}.tgz data", shell=True, check=True)
