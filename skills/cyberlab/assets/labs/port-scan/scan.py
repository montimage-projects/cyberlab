"""Port-scan lab client. MODE=attack: TCP connect scan of a port range. MODE=benign: 5 HTTP GETs.

Usage: scan.py <host> <attack|benign> [first-last]     standard library only
"""
import socket
import sys
import time

host, mode = sys.argv[1], sys.argv[2]
first, last = (int(x) for x in (sys.argv[3] if len(sys.argv) > 3 else "1-1024").split("-"))
time.sleep(2)  # let tcpdump start
if mode == "attack":
    open_ports = []
    for port in range(first, last + 1):
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
        s.close()
    print(f"scanned {last - first + 1} ports, open: {open_ports}")
elif mode == "benign":
    for _ in range(5):
        s = socket.create_connection((host, 80), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: victim\r\nConnection: close\r\n\r\n")
        print(s.recv(64).split(b"\r\n")[0].decode())
        s.close()
        time.sleep(0.5)
else:
    sys.exit(f"Error: mode '{mode}' is not attack or benign.")
