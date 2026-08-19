"""Threading & Multiprocessing fixture."""

import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

counter = 0
lock = threading.Lock()

def worker():
    global counter
    with lock:
        counter += 1

def start_workers():
    t = threading.Thread(target=worker)
    t.start()
    p = multiprocessing.Process(target=worker)
    p.start()
    with ThreadPoolExecutor() as pool:
        pool.submit(worker)
