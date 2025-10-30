import socket

HOST = '127.0.0.1'
PORT = 12345

clients = set()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST, PORT))

print(f"[SERVER] UDP chat running on {HOST}:{PORT}")

while True:
    data, addr = s.recvfrom(1024)
    msg = data.decode().strip()

    # add new client
    clients.add(addr)
    print(f"{addr}: {msg}")

    # prepare message to send to all client
    full_msg = f"{addr}: {msg}"

    # send to all connected clients
    for client in clients:
        s.sendto(full_msg.encode(), client)
