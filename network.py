import asyncio
import json
import sys

class Peer:
    # Class variable to hold shutdown event, shared across all instances
    shutdown_event = asyncio.Event()

    def __init__(self, host='127.0.0.1', port=65432, password="1234", name="Bob", is_server=False):
        self.host = host
        self.port = port
        self.password = password
        self.name = name
        self.is_server = is_server

    def pack(self, content):
        return json.dumps({
            "name": self.name,
            "content": content.strip()
        }).encode()

    def unpack(self, data):
        return json.loads(data.decode())

    async def send_loop(self, writer):
        while not Peer.shutdown_event.is_set():  # Use the class variable
            try:
                msg = await asyncio.get_event_loop().run_in_executor(None, input, "Enter message: ")
                writer.write(self.pack(msg))
                await writer.drain()
            except asyncio.CancelledError:
                break
            except EOFError:
                Peer.shutdown_event.set()
                break

    async def receive_loop(self, reader, other_name="Peer"):
        while not Peer.shutdown_event.is_set():  # Use the class variable
            try:
                data = await reader.read(1024)
                if not data:  # Peer disconnected
                    print(f"{other_name} disconnected")
                    Peer.shutdown_event.set()  # Signal to stop send loop
                    break
                received = self.unpack(data)
                print(f"[{received.get('name')}] {received.get('content')}")
            except asyncio.CancelledError:
                break

    async def handle_connection(self, reader, writer):
        other_host, other_port = writer.get_extra_info('peername')
        print(f"Connection from [{other_host}:{other_port}]")

        data = await reader.read(1024)
        if not data:
            print(f"[{other_host}:{other_port}] disconnected")
            writer.close()
            await writer.wait_closed()
            return

        packet = self.unpack(data)
        other_name = packet.get("name")
        content = packet.get("content")

        if content != self.password:
            writer.write(self.pack("reject"))
            await writer.drain()
            print(f"{other_name} sent incorrect password: {content} (expected: {self.password}) — closing connection")
            writer.close()
            await writer.wait_closed()
            return

        writer.write(self.pack("accept"))
        await writer.drain()

        # Using asyncio.gather to run both send_loop and receive_loop concurrently
        await asyncio.gather(
            self.receive_loop(reader, other_name),
            self.send_loop(writer)
        )

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        print(f"Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def start_client(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        print(f"Connected to {self.host}:{self.port}")
        writer.write(self.pack(self.password))
        await writer.drain()

        data = await reader.read(1024)
        if not data:
            print(f"{self.host}:{self.port} disconnected")
            writer.close()
            await writer.wait_closed()
            return

        packet = self.unpack(data)
        other_name = packet.get("name")
        content = packet.get("content")

        if content == "reject":
            print(f"{other_name} rejected the password")
            writer.close()
            await writer.wait_closed()
            return

        print(f"{other_name} accepted the password")

        # Using asyncio.gather to run both send_loop and receive_loop concurrently
        await asyncio.gather(
            self.receive_loop(reader, other_name),
            self.send_loop(writer)
        )

    async def run(self):
        if self.is_server:
            await self.start_server()
        else:
            await self.start_client()

            
if __name__ == "__main__":
    def main():
        # Prompt the user to choose between server or client
        mode = input("Start as server or client? (s/c): ").strip().lower()

        if mode == 's':
            server = Peer(name="Bob", is_server=True)
            asyncio.run(server.run())
        elif mode == 'c':
            client = Peer(name="Alice", is_server=False, password = "fart")
            asyncio.run(client.run())
        else:
            print("Invalid option. Please enter 's' for server or 'c' for client.")

    try:
        main()
    except KeyboardInterrupt:
        print("\n[System] Exiting...")
        sys.exit(0)
