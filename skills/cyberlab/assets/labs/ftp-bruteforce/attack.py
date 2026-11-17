# FTP lab client (stdlib ftplib, nothing to install on the internal network).
"""FTP lab client. MODE=attack: 8 failed logins (brute force). MODE=benign: one successful login."""
import ftplib, sys, time
host, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "attack")
if mode not in ("attack", "benign"):
    sys.exit(f"Error: mode '{mode}' is not attack or benign.")
time.sleep(3)  # let tcpdump start
passwords = ["123456", "password", "admin", "qwerty", "letmein", "root", "test", "ftp"] if mode == "attack" else ["testpass"]
for pw in passwords:
    try:
        f = ftplib.FTP(host, timeout=5); f.login("testuser", pw); print("login ok", pw); f.nlst(); f.quit()
    except ftplib.error_perm as e:
        print("failed", pw, e)
