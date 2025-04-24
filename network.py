import asyncio
import json
import sys

class Peer:
    # Class variable to hold shutdown event, shared across all instances
    shutdown_event = asyncio.Event()

    def __init__(self, host='127.0.0.1', port=65432, password="1234", name="Bob", is_server=True):
        self.host = host
        self.port = port
        self.password = password
        self.name = name
        self.is_server = is_server

        self.writer = 0
        self.reader = 0


        if(is_server == True):
            print(f"Starting server listenting on [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")
        else: print(f"Starting client connecting to [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")

    def pack(self, content):
        return json.dumps({
            "name": self.name,
            "content": content.strip()
        }).encode()

    def unpack(self, data):
        return json.loads(data.decode())

    async def send(self, msg):
        try: 
            self.writer.write(self.pack(msg))
            await self.writer.drain()
        except asyncio.CancelledError:
            return 

    async def receive_loop(self, other_name="Peer"):
        while not Peer.shutdown_event.is_set():  # Use the class variable
            try:
                data = await self.reader.read(1024)
                if not data:  # Peer disconnected
                    print(f"{other_name} disconnected")
                    Peer.shutdown_event.set()  # Signal to stop send loop
                    break
                received = self.unpack(data)
                print(f"[{received.get('name')}] {received.get('content')}")
            except asyncio.CancelledError:
                break

    async def handle_connection(self, reader, writer):
        self.reader = reader 
        self.writer = writer
        other_host, other_port = self.writer.get_extra_info('peername')
        print(f"Connection from [{other_host}:{other_port}]")

        data = await self.reader.read(1024)
        if not data:
            print(f"[{other_host}:{other_port}] disconnected")
            self.writer.close()
            await self.writer.wait_closed()
            return

        packet = self.unpack(data)
        other_name = packet.get("name")
        content = packet.get("content")

        if content != self.password:
            self.writer.write(self.pack("reject"))
            await self.writer.drain()
            print(f"{other_name} sent incorrect password: {content} (expected: {self.password}) — closing connection")
            self.writer.close()
            await self.writer.wait_closed()
            return

        self.writer.write(self.pack("accept"))
        await self.writer.drain()

        # Using asyncio.gather to run both send_loop and receive_loop concurrently
        # await asyncio.gather(
        #     self.receive_loop(reader, other_name),
        #     self.send_loop(writer)
        # )

        await self.receive_loop(other_name)

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        print(f"Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def start_client(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        print(f"Connected to {self.host}:{self.port}")
        self.writer.write(self.pack(self.password))
        await self.writer.drain()

        data = await self.reader.read(1024)
        if not data:
            print(f"{self.host}:{self.port} disconnected")
            self.writer.close()
            await self.writer.wait_closed()
            return

        packet = self.unpack(data)
        other_name = packet.get("name")
        content = packet.get("content")

        if content == "reject":
            print(f"{other_name} rejected the password")
            self.writer.close()
            await self.writer.wait_closed()
            return

        print(f"{other_name} accepted the password")

        # Using asyncio.gather to run both send_loop and receive_loop concurrently
        # await asyncio.gather(
        #     self.receive_loop(reader, other_name),
        #     self.send_loop(writer)
        # )

        await self.receive_loop(other_name)

    def run(self):

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if self.is_server:
            self.loop.run_until_complete(self.start_server())
        else:
            self.loop.run_until_complete(self.start_client())

            
if __name__ == "__main__":
    def main():
        # Prompt the user to choose between server or client
        mode = input("Start as server or client? (s/c): ").strip().lower()

        if mode == 's':
            server = Peer(name="Bob", is_server=True, password = "fart")
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
