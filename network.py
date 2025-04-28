import asyncio
import json
import sys

#for base key gen outside of class
from Crypto.PublicKey import DSA

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

        self.on_message = None

        #Other
        self.other_name = "NAME_UNKNOWN_ERROR"
        self.other_host = 0
        self.other_port = 0

        self.crypto = None

        if(is_server == True):
            print(f"Starting server listenting on [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")
        else: print(f"Starting client connecting to [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")

    def pack(self, content, type):

        raw = None
        if(type in ["message","name","password","pub"]):
            raw = json.dumps({
                "type": type,
                "content": content
            }).encode()
            print(f"Packed {type} data: {raw}")
            return raw 
        
        elif(type == "pqg_pub"):
            print(f"Packed {type} data: {content}")
            return content #in this case this is a custom json packing method that is easier to handle outside this method

        return(raw)

    def unpack(self, data):
        return json.loads(data.decode())

    async def send(self, content, type):
        try: 
            self.writer.write(self.pack(content,type))
            await self.writer.drain()
        except asyncio.CancelledError:
            return #TODO HANDLE ERROR
        
    async def receive(self, expected_type = None):
        data = await self.reader.read(4096)

        if not data: #check for disconnect
            print(f"[{self.other_host}:{self.other_port}] disconnected")
            Peer.shutdown_event.set() #TODO CODE THIS OR SOMETHING
            return 
        

        print(f"Received raw data: {data}")
        packet = self.unpack(data)
        type = packet.get("type")

        if (expected_type != None) and (expected_type != type):
            print(f"Received type [{type}], expected type [{expected_type}]")
            return #TODO HANDLE
        
        if type == "message":
            content = packet.get("content")
            #handle message
            print(f"Handling message: [{self.other_name}] {content}")

            #gui stuffs :) 
            if self.on_message != None: 
                self.on_message(self.other_name, content)
            else:
                print("on_message undefined error")
                #TODO HANDLE THIS ERROR? s

        elif type == "name":
            content = packet.get("content")
            #set name
            self.other_name == content

        # Non-void types, must be handled outside of this function, so the packet is returned

        elif type == "password":
            content = packet.get("content")
            return content 
        elif type == "pqg_pub":
            return packet
        elif type == "pub":
            return packet.get("content")

        return None

    async def receive_loop(self):
        while not Peer.shutdown_event.is_set():
            try:
                packet = await self.receive()
            except asyncio.CancelledError:
                break

    #SERVER STARTING ROUTINE
    async def handle_connection(self, reader, writer):
        self.reader = reader 
        self.writer = writer

        other_host, other_port = self.writer.get_extra_info('peername')

        print(f"Connection from [{other_host}:{other_port}]")

        #PASSWORD HANDLING

        content = await self.receive("password")

        if content != self.password:
            await self.send("reject","password")
            print(f"[{other_host}:{other_port}] sent incorrect password: {content} (expected: {self.password}) — closing connection")
            Peer.shutdown_event.set() #TODO HANDLE THIS SHIT
            return
        
        await self.send("accept","password")

        #NAME HANDLING

        await self.receive("name") #naming stuff handled here
        await self.send(self.name,"name")

        #CRYPTO

        new_crypto = Crypto()

        content = json.dumps({
                "type": "pqg_pub",
                "p": str(new_crypto.p), #p
                "q": str(new_crypto.q), #q
                "g": str(new_crypto.g), #g
                "pub": str(new_crypto.key_public) #public key
        }).encode()

        await self.send(content,"pqg_pub") #base and server pub sent to client

        other_pub = int(await self.receive("pub"))

        new_crypto.derive_shared_key(other_pub) #derive the shared key from clients pub

        self.crypto = new_crypto #establish new cryptography method

        print(f"Server Public key: {self.crypto.key_public}")
        print(f"Server Shared key: {self.crypto.key_shared}")

        #Main chat loop

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
        content = await self.receive("password")

        if content == "reject":
            print(f"[{self.host}:{self.port}] rejected the password")
            self.writer.close()
            await self.writer.wait_closed()

            #TODO HANDLE THIS

            return

        print(f"[{self.host}:{self.port}] accepted the password") #moving on from here

        #NAME HANDLING

        await self.send(self.name,"name")
        await self.receive("name")#void handling

        #CRYPTO

        content = await self.receive("pqg_pub")

        pqg = []
        pqg.append(int(content.get("p")))
        pqg.append(int(content.get("q")))
        pqg.append(int(content.get("g")))

        other_pub = int(content.get("pub"))

        new_crypto = Crypto(pqg)
        new_crypto.derive_shared_key(other_pub)

        my_pub = str(new_crypto.key_public)

        await self.send(my_pub,"pub")

        self.crypto = new_crypto

        print(f"Client Public key: {self.crypto.key_public}")
        print(f"Client Shared key: {self.crypto.key_shared}")
        

        #chat loop 

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
