import socket
import concurrent.futures
from contextlib import closing

def scan(target, result):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        if sock.connect_ex(target) == 0:
            result.append(target[1])

def portscanner(targets):
    result = []
    threadpool = concurrent.futures.ThreadPoolExecutor(
        max_workers=1000)
    futures = (threadpool.submit(scan, target, result) for target in targets)
    for i in concurrent.futures.as_completed(futures):
        pass
    return result
