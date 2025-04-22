import asyncio

#TODO MERGE THESE TWO CLASSES INTO ONE UNIFIED CLASS


class PeerServer:
    def __init__(self, host='127.0.0.1', port=65432, password="1234"):
        self.host = host
        self.port = port
        self.password = password

    async def handle_connection(self, reader, writer):
        other_host, other_port = writer.get_extra_info('peername')
        print(f"[Server] Connection from {other_host}:{other_port}")

        # Handle password exchange
        data = await reader.read(1024)
        if not data:
            writer.close()
            await writer.wait_closed()

        clientPassword = data.decode()

        if clientPassword.strip() == self.password:
            writer.write("accept".encode())  # Accept password
            await writer.drain()
        else:
            writer.write("reject".encode())  # Reject password
            await writer.drain()
            print(f"[Server] Incorrect password. Closing connection")
            writer.close()
            await writer.wait_closed()
            return

        # Once password is accepted, allow continuous sending and receiving
        async def send():
            while True:
                msg = await asyncio.get_event_loop().run_in_executor(None, input, "[Server] Enter msg: ")
                writer.write((msg + "\n").encode())  # Send message to client
                await writer.drain()

        async def receive():
            while True:
                data = await reader.read(1024)
                if not data:
                    print(f"[Server] Peer {other_host}:{other_port} disconnected.")
                    break
                msg = data.decode()
                print(f"[Server] Received: {msg}")

        # Run both send and receive functions concurrently
        await asyncio.gather(receive(), send())

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        print(f"[Server] Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def run(self):
        await self.start_server()

import asyncio

class PeerClient:
    def __init__(self, host='127.0.0.1', port=65432, password="1234"):
        self.host = host
        self.port = port
        self.password = password

    async def start_client(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        print(f"[Client] Connected to {self.host}:{self.port}")

        # Send password
        writer.write(self.password.encode())
        await writer.drain()

        # Check server response
        serverResponse = await reader.read(1024)
        if serverResponse.decode() == "reject":
            print("[Client] Server rejects the password")
            writer.close()
            await writer.wait_closed()
            return
        
        print("[Client] Server accepts the password")

        # Handle receiving messages from the server
        async def receive():
            while True:
                data = await reader.read(1024)
                if not data:
                    print("[Client] Server disconnected.")
                    break
                print(f"[Server] {data.decode().strip()}")  # Display received message

        # Handle sending messages to the server
        async def send():
            while True:
                msg = await asyncio.get_event_loop().run_in_executor(None, input, "Enter message: ")
                writer.write((msg + "\n").encode())  # Send message to server
                await writer.drain()

        # Run both send and receive concurrently
        await asyncio.gather(receive(), send())

    async def run(self):
        await self.start_client()

### TESTING, THIS SHOULD BE DONE IN MAIN.py

if __name__ == "__main__":
    import sys

    def main():
        # Prompt the user to choose between server or client
        mode = input("Start as server or client? (s/c): ").strip().lower()

        if mode == 's':
            server = PeerServer()
            # Run the server's asynchronous logic inside the event loop
            asyncio.run(server.run())
        elif mode == 'c':
            client = PeerClient()
            # Run the client's asynchronous logic inside the event loop
            asyncio.run(client.run())
        else:
            print("Invalid option. Please enter 's' for server or 'c' for client.")

    try:
        main()  # Call the main function synchronously
    except KeyboardInterrupt:
        print("\n[System] Exiting...")
        sys.exit(0)