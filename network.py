import socket
import threading 

class Peer:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port

    def handle_connection(self, conn, addr):
        print(f"[Server] Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[Server] Received from {addr}: {data.decode()}")
        conn.close()

    def start_receiver(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver.bind((self.host, self.port))
        receiver.listen()
        print(f"[Server] Listening on {self.host}:{self.port}")
        while True:
            conn, addr = receiver.accept()
            thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
            thread.start()

    def start_sender(self):
        while True:
            other_host = input("Enter peer IP (or 'quit'): ")
            if other_host.lower() == 'quit':
                break
            try:
                other_port = int(input("Enter peer port: "))
                message = input("Message to send: ")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((other_host, other_port))
                    s.sendall(message.encode())
            except Exception as e:
                print(f"[Client] Error: {e}")

    def run(self):
        print("[Peer] Starting peer...")
        threading.Thread(target=self.start_sender, daemon=True).start()
        self.start_receiver()

if __name__ == "__main__":
    peer = Peer("127.0.0.1", 25565)
    peer.run()
