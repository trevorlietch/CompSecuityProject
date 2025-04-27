import asyncio
import json
import sys

#CRYPTO
from aes import Crypto

class Peer:
    # Class variable to hold shutdown event, shared across all instances
    shutdown_event = asyncio.Event()

    def __init__(self, host='127.0.0.1', port=65432, password="1234", name="Bob", is_server=True):
        #Parameters
        self.host = host
        self.port = port
        self.password = password
        self.name = name
        self.is_server = is_server

        #Networking 
        self.writer = 0
        self.reader = 0

        self.on_message = 0

        #Other
        self.other_name = "NAME_UNKNOWN_ERROR"
        self.other_host = 0
        self.other_port = 0

        self.crypto = None

        if(is_server == True):
            print(f"Starting server listenting on [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")
        else: print(f"Starting client connecting to [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")

    def pack(self, content, type):

        raw = json.dumps({
            "type": type,
            "content": content
        }).encode()

        return(raw)

    def unpack(self, data):
        return json.loads(data.decode())

    async def send(self, content, type):
        try: 
            self.writer.write(self.pack(content,type))
            await self.writer.drain()
        except asyncio.CancelledError:
            return #TODO HANDLE ERROR
        
    async def receive(self):
        data = await self.reader.read(1024)
        if not data:
            print(f"[{self.other_host}:{self.other_port}] disconnected")
            Peer.shutdown_event.set() #TODO CODE THIS OR SOMETHING
            return 
        return(self.unpack(data))
    
    def process_packet(self,packet,expected_type = None):
        type = packet.get("type")
        content = packet.get("content")

        if (expected_type != None) and (expected_type != type):
            print(f"Received type [{type}], expected {expected_type}")
            return #TODO HANDLE
        
        if type == "message":
            #handle message
            print(f"Handling message: [{self.other_name}] {content}")

            #gui stuffs :) 
            if self.on_message != 0: 
                self.on_message(self.other_name, content)
            else:
                print("on_message undefined error")
                #TODO HANDLE THIS ERROR? s
        elif type == "name":
            #set name
            self.other_name == content

        # Non-void types, must be handled outside of this function

        elif type == "password":
            return content #handled by respective server and client loops
        elif type == "key":
            return content #handled by respective server and client loops

    async def receive_loop(self):
        while not Peer.shutdown_event.is_set():
            try:
                packet = await self.receive()
                self.process_packet(packet)

            except asyncio.CancelledError:
                break

    #SERVER STARTING ROUTINE
    async def handle_connection(self, reader, writer):
        self.reader = reader 
        self.writer = writer

        other_host, other_port = self.writer.get_extra_info('peername')

        print(f"Connection from [{other_host}:{other_port}]")

        #PASSWORD HANDLING

        packet = await self.receive()
        content = self.process_packet(packet,"password")

        if content != self.password:
            await self.send("reject","password")
            print(f"[{other_host}:{other_port}] sent incorrect password: {content} (expected: {self.password}) — closing connection")
            Peer.shutdown_event.set() #TODO HANDLE THIS SHIT
            return
        
        await self.send("accept","password")

        #NAME HANDLING

        packet = await self.receive()
        self.process_packet(packet,"name") #void

        await self.send(self.name,"name")

        #CRYPTO

        packet = await self.receive()
        content = self.process_packet(packet, "key") #base_key

        base.key

        self.crypto = Crypto()



        self.crypto.derive_key_from_secret(content) 
        print(self.crypto.key_shared.decode())

        await self.send(self.crypto.key_public, "key")

        print(f"Client Shared Key: {self.crypto.key_shared.decode()}")

        await self.receive_loop()

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        print(f"Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    #CLIENT STARTING ROUTINE
    async def start_client(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        print(f"Connected to {self.host}:{self.port}")

        #PASSWORD HANDLING
        await self.send(self.password,"password")

        packet = await self.receive()
        content = self.process_packet(packet,"password")

        if content == "reject":
            print(f"[{self.host}:{self.port}] rejected the password")
            self.writer.close()
            await self.writer.wait_closed()

            #TODO HANDLE THIS

            return

        print(f"[{self.host}:{self.port}] accepted the password")

        #NAME HANDLING

        await self.send(self.name,"name")

        packet = await self.receive()
        self.process_packet(packet,"name") #void handling

        #CRYPTO

        await self.send(self.crypto.key_public,"key")
        print(f"Sent public key: {self.crypto.key_public}")

        packet = await self.receive()
        content = self.process_packet(packet, "key")

        self.crypto.derive_key_from_secret(content) #shared key 

        print(f"Client Shared Key: {self.crypto.key_shared}")

        await self.receive_loop()

    #PEER START ROUTINE
    def run(self):

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if self.is_server:
            self.loop.run_until_complete(self.start_server())
        else:
            self.loop.run_until_complete(self.start_client())


#TESTING, IGNORE FOR FULL USE
            
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
