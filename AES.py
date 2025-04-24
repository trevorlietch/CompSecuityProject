import base64
import os
import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

BLOCK_SIZE = 16
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 100_000
MESSAGE_LIMIT = 10

def derive_key_from_secret(secret: str) -> bytes:
    return SHA256.new(secret.encode()).digest()

def aes_encrypt(message: str, key: bytes) -> str:
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encoded: str, key: bytes) -> str:
    try:
        combined = base64.b64decode(encoded)
        iv = combined[:BLOCK_SIZE]
        ciphertext = combined[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return decrypted.decode()
    except Exception as e:
        return f"[Decryption failed: {e}]"
    
class SecureSession:
    def __init__(self, conn, is_initiator):
        self.conn = conn
        self.is_initiator = is_initiator
        self.message_count = 0
        self._generate_dh_keypair()
        self._exchange_keys()

    def _generate_dh_keypair(self):
        self.dh_key = DSA.generate(2048)
        self.public_key_bytes = self.dh_key.publickey().export_key()

    def _exchange_keys(self):
        if self.is_initiator:
            self.conn.sendall(self.public_key_bytes)
            their_pub_bytes = self.conn.recv(4096)
        else:
            their_pub_bytes = self.conn.recv(4096)
            self.conn.sendall(self.public_key_bytes)

        their_key = DSA.import_key(their_pub_bytes)
        shared_secret = pow(their_key.y, self.dh_key.x, self.dh_key.p)
        self.shared_key = derive_key_from_secret(str(shared_secret))
        self.message_count = 0;

    def _check_key_rotation(self):
        if self.message_count >= MESSAGE_LIMIT:
            self._generate_dh_keypair()
            self._exchange_keys()

    def encrypt_and_send(self, message: str):
        self._check_key_rotation()
        encrypted = aes_encrypt(message, self.shared_key)
        self.conn.sendall(encrypted.encode() + b"\n")
        self.message_count += 1

    def receive_and_decrypt(self):
        self._check_key_rotation()
        encode = b""
        while not encoded.endswith(b"\n"):
            encoded += self.conn.recv(1024)

        message = aes_decrypt(encoded.decode().strip(), self.shared_key)
        self.message_count += 1
        return message