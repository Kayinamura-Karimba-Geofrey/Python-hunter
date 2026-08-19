"""Races and Deadlocks fixture."""

import threading
import os

lock1 = threading.Lock()
lock2 = threading.Lock()

def task_a():
    with lock1:
        with lock2:
            pass

def task_b():
    with lock2:
        with lock1:
            pass

def check_and_open(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return None
