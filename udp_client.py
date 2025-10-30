import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

def receive(sock):
    while True:
        try:
            data, _ = sock.recvfrom(1024)
            print(data.decode())
        except:
            break

# Create UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Start thread to listen for messages
threading.Thread(target=receive, args=(s,), daemon=True).start()

print("Connected to UDP chat. Type messages and press Enter. Type 'exit' to quit.")

while True:
    msg = input()
    if msg.lower() == "exit":
        break
    s.sendto(msg.encode(), (HOST, PORT))

s.close()
print("Disconnected.")
