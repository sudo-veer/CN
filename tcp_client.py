import socket
import threading
#import
HOST = '127.0.0.1'
PORT = 12345

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            print(data.decode(), end="")
        except:
            break

def start_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Connected to the chat server. Type messages and press Enter.\n")

    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

    while True:
        msg = input()
        if msg.lower() == "exit":
            s.sendall(msg.encode())
            break
        s.sendall(msg.encode())

    s.close()
    print("Disconnected from server.")

if __name__ == "__main__":
    start_client()
