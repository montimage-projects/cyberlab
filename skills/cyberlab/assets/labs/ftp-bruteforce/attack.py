# FTP lab client (stdlib ftplib, nothing to install on the internal network).
"""FTP lab client. MODE=attack: 8 failed logins (brute force). MODE=benign: one successful login.

A real server may close a session instead of answering (e.g. a crashing or overloaded server):
that attempt is reported as "dropped" and the run goes on. Exit 1 when the mode's goal is not met:
fewer than 5 "530" replies (attack) or no successful login (benign).
"""
import ftplib
import sys
import time

host, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "attack")
if mode not in ("attack", "benign"):
    sys.exit(f"Error: mode '{mode}' is not attack or benign.")
time.sleep(3)  # let tcpdump start
passwords = ["123456", "password", "admin", "qwerty", "letmein", "root", "test", "ftp"] if mode == "attack" else ["testpass"]
failed = ok = 0
for pw in passwords:
    try:
        f = ftplib.FTP(host, timeout=10)
        f.login("testuser", pw)
        print("login ok", pw)
        ok += 1
        f.nlst()
        f.quit()
    except ftplib.error_perm as e:
        print("failed", pw, e)
        failed += str(e).startswith("530")
    except (EOFError, OSError) as e:
        print("dropped", pw, type(e).__name__)
print(f"{mode}: {failed} failed login(s), {ok} successful")
if (mode == "attack" and failed < 5) or (mode == "benign" and ok < 1):
    sys.exit(f"Error: {mode} goal not met ({failed} failed, {ok} ok).")
