import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

clients = []

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    conn.sendall("Welcome to the chat! Type 'exit' to leave.\n".encode())

    while True:
        try:
            msg = conn.recv(1024).decode().strip()
            if not msg:
                break
            if msg.lower() == "exit":
                conn.sendall("Goodbye!\n".encode())
                break

            full_msg = f"{addr}: {msg}\n"
            print(full_msg, end="")

            # broadcast to all clients except sender yes
            
            for c in clients:
                if c != conn:
                    c.sendall(full_msg.encode())
        except:
            break

    print(f"[DISCONNECTED] {addr}")
    clients.remove(conn)
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
