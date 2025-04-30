import asyncio
import json
import sys
from datetime import datetime

#CRYPTO
from security import Crypto

class Peer:
    # Class variable to hold shutdown event, shared across all instances
    def __init__(self, host='127.0.0.1', port=65432, password="1234", name="Bob", is_server=True):
        #Parameters
        self.host = host
        self.port = port
        self.password = password
        self.name = name
        self.is_server = is_server
        self.packet_size = 4096

        #Networking 
        self.writer = 0
        self.reader = 0

        self.on_message = None
        self.receive_task = None

        self.reader_lock = asyncio.Lock()

        #self.reader_lock = asyncio.Lock()

        #Log
        self.log_cutoff = 100

        #Crypto
        self.crypto = None
        self.crypto_lock = asyncio.Lock()

        #these are server only crypto stuff
        self.interval = 10
        self.timeout = 1 
        self.crypto_refresh_task = None

        #Other Peer
        self.other_name = "NAME_UNKNOWN_ERROR"
        self.other_host = 0
        self.other_port = 0

    def log(self, message, separate = False, trim = True):
        current_time = datetime.now().strftime("%H:%M:%S")

        role = "Server" if self.is_server else "Client"

        if (len(message) > self.log_cutoff) and trim:
            message = message[:self.log_cutoff - 3] + "..."

        if separate: print(f"\n[{role}][{current_time}] {message}\n")
        else: print(f"[{role}][{current_time}] {message}")

    def shutdown(self, message):
        self.log(message)
        self.log("Shutting down")
        sys.exit()

    def pack(self, content, type):

        packet = None
        if(type in ["message","name","password","pub"]):
            packet = json.dumps({
                "type": type,
                "content": content
            })
        
        elif(type == "pqg_pub"):
            packet = content #in this case this is a custom json packing method that is easier to handle outside this method

        self.log(f"Sending packet: {packet}")
        return(packet.encode())

    def unpack(self, packet):
        return json.loads(packet.decode())

    async def send(self, content, type):
        try:
            # Pack the content
            packet = self.pack(content, type)

            async with self.crypto_lock:
                if self.crypto:
                    packet = self.crypto.aes_encrypt(packet) 
                    self.log(f"Packet encrypted to: {packet}")

            # Check if the packed content size is larger than 4096 bytes
            if len(packet) > self.packet_size:
                self.shutdown(f"Data size of {len(packet)} bytes is larger than limit {self.packet_size} bytes")
            
            # Send the packed content
            self.writer.write(packet)
            await self.writer.drain()

        except asyncio.CancelledError:
            self.shutdown("asyncio.Cancelled Error")
        
    async def receive(self, expected_type=None):
        #async with self.reader_lock: 
        try: 
            packet = await asyncio.wait_for(self.reader.read(self.packet_size), timeout = self.timeout)
        except asyncio.TimeoutError:
            return  #just time out, don't log or error
        if not packet:
            self.shutdown(f"[{self.other_host}:{self.other_port}] Disconnected")
        
        if self.crypto:
            self.log(f"Decrypting packet from: {packet}")
            try:
                packet = self.crypto.aes_decrypt(packet)
            except Exception as e:
                self.log(f"Decryption failed, most likely older packet: {e}")
                return

        try: 
            packet = self.unpack(packet)
        except Exception as e:
            self.log(f"Unpacking failed, raw packet: {packet}, error: {e}")
            return

        self.log(f"Received packet: {packet}")
        
        type = packet.get("type")

        if (expected_type is not None) and (expected_type != type):
            self.log(f"Received type [{type}], expected type [{expected_type}]")
            return 

        if type == "message":
            content = packet.get("content")
            if self.on_message:
                self.on_message(self.other_name, content)
            else:
                self.log("on_message undefined error")

        elif type == "name":
            self.other_name = packet.get("content")

        elif type == "password":
            return packet.get("content")

        elif type == "pqg_pub":
            if not self.is_server:
                await self.crypto_routine_client(packet)
            else:
                self.shutdown("ERROR: Received pqg_pub packet as the server")

        elif type == "pub": 
            #print(f"Inside type == pub, Pub received for sure: {packet.get("content")}")
            return packet.get("content")
        return

    async def receive_loop(self):
        try:
            async with self.reader_lock:
                await self.receive()
        except asyncio.CancelledError:
            self.shutdown("asyncio.Cancelled Error")
            
    
    async def crypto_refresh_loop(self):
        while not Peer.shutdown_event.is_set():
            await asyncio.sleep(self.interval)
            self.log("Refreshing cryptographic keys", separate=True)

            async with self.reader_lock:
                await self.crypto_routine_server()

    async def crypto_routine_server(self):
        self.log("Generating new Diffie-Hellman key set", separate = True)

        #self.crypto_event.clear()
        new_crypto = Crypto()

        content = json.dumps({
                "type": "pqg_pub",
                "p": str(new_crypto.p), #p
                "q": str(new_crypto.q), #q
                "g": str(new_crypto.g), #g
                "pub": str(new_crypto.key_public) #public key
        })

        await self.send(content,"pqg_pub") #base and server pub sent to client

        pub_value = None 
        while pub_value == None:
            pub_value = await self.receive("pub")
            self.log(f"Got raw client public key value: {pub_value} of python type {type(pub_value)}")

        other_pub = int(pub_value)

        new_crypto.derive_shared_key(other_pub) #derive the shared key from clients pub

        async with self.crypto_lock:
            self.crypto = new_crypto

        #self.crypto_event = false
        self.crypto_flag = False

        self.log(f"Shared key: {self.crypto.key_shared}\n")


    async def crypto_routine_client(self, content):
        self.log("Received new Diffie-Hellman key set", separate = True)

        #self.crypto_event.set()

        pqg = []
        pqg.append(int(content.get("p")))
        pqg.append(int(content.get("q")))
        pqg.append(int(content.get("g")))

        other_pub = int(content.get("pub"))

        new_crypto = Crypto(pqg)
        new_crypto.derive_shared_key(other_pub)

        my_pub = str(new_crypto.key_public)

        await self.send(my_pub,"pub")

        async with self.crypto_lock:
            self.crypto = new_crypto

        #self.crypto_event.clear()

        self.log(f"Shared key: {self.crypto.key_shared}\n")

    #SERVER STARTING ROUTINE
    async def handle_connection(self, reader, writer):
        self.log(f"Connected to [{self.host}:{self.port}], expecting password [{self.password}]")

        self.reader = reader 
        self.writer = writer

        self.other_host, self.other_port = self.writer.get_extra_info('peername')

        self.log(f"Connection from [{self.other_host}:{self.other_port}]")

        #PASSWORD HANDLING

        content = await self.receive("password")

        if content != self.password:
            await self.send("reject","password")
            self.log(f"[{self.other_host}:{self.other_port}] sent an incorrect password [{content}], expected: [{self.password}]")
            self.log("Closing connection")
            return
        
        self.log(f"[{self.other_host}:{self.other_port}] sent the correct password: {content}")
        await self.send("accept","password")

        #NAME HANDLING

        await self.receive("name") #naming stuff handled here
        await self.send(self.name,"name")

        #CRYPTO
        
        await self.crypto_routine_server() #server always initiates this routine and client responds correspondingly 

        #Main chat loop

        self.log("Starting receive and crypto loops", True)

        self.receive_task = asyncio.create_task(self.receive_loop())
        self.crypto_refresh_task = asyncio.create_task(self.crypto_refresh_loop())

        await asyncio.gather(
            self.receive_task,
            self.crypto_refresh_task
        )

        return

    async def start_server(self):
        server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        self.log(f"Listening for connections on [{self.host}:{self.port}], current name is {self.name}")
        async with server:
            await server.serve_forever()

    #CLIENT STARTING ROUTINE
    async def start_client(self):
        self.log(f"Attempting to connect to [{self.host}:{self.port}] with password [{self.password}], as name [{self.name}]")

        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.log(f"Connected to {self.host}:{self.port}")

        #PASSWORD HANDLING
        await self.send(self.password,"password")
        content = await self.receive("password")

        if content == "reject":
            self.shutdown(f"[{self.host}:{self.port}] rejected password: {self.password}")

        self.log(f"[{self.host}:{self.port}] accepted password: {self.password}") #moving on from here

        #NAME HANDLING

        await self.send(self.name,"name")
        await self.receive("name")#void handling

        #CRYPTO

        await self.receive("pqg_pub") #Client waits for this packet then initiates crypto routine
    
        #chat loop 

        self.log("Starting receive loop", True)

        self.receive_task = asyncio.create_task(self.receive_loop())
        await self.receive_task

    #PEER START ROUTINE
    def run(self):
        role = "Server" if self.is_server else "Client"
        self.log(f"Starting Peer with mode [{role}]...")

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if self.is_server:
            self.loop.run_until_complete(self.start_server())
        else:
            self.loop.run_until_complete(self.start_client())