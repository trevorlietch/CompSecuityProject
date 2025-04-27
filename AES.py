import base64
import os
import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256


class Crypto:

    def __init__(self):
        self.public_key = DSA.generate(2048)
        self.private_key = DSA.generate(2048)

        self.BLOCK_SIZE = 16
        base_key = DSA.generate(2048)
        p = base_key.p
        q = base_key.q
        g = base_key.g

        user_private = int.from_bytes(os.urandom(32), 'big') % q
        user_public = pow(g, alice_x, p)

    def derive_key_from_secret(self,secret: str) -> bytes:
        return SHA256.new(str(secret).encode()).digest()

    def aes_encrypt(self,message: str, key: bytes) -> str:
        iv = os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(message.encode(), self.BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self,encoded: str, key: bytes) -> str:
        try:
            combined = base64.b64decode(encoded)
            iv = combined[:self.BLOCK_SIZE]
            ciphertext = combined[self.BLOCK_SIZE:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)
            return decrypted.decode()
        except Exception as e:
            return f"[Decryption failed: {e}]"
        
    def derive_key_from_secret(secret: int) -> bytes:
        return SHA256.new(str(secret).encode()).digest()

if __name__ == "__main__":
    base_key = DSA.generate(2048)
    p = base_key.p
    q = base_key.q
    g = base_key.g

    # Generate Alice's key pair with shared params
    alice_x = int.from_bytes(os.urandom(32), 'big') % q
    alice_y = pow(g, alice_x, p)

    # Generate Bob's key pair with shared params
    bob_x = int.from_bytes(os.urandom(32), 'big') % q
    bob_y = pow(g, bob_x, p)

    # Exchange public keys and compute shared secrets
    alice_shared_secret = pow(bob_y, alice_x, p)
    bob_shared_secret = pow(alice_y, bob_x, p)

    # Derive AES key
    alice_aes_key = derive_key_from_secret(alice_shared_secret)
    bob_aes_key = derive_key_from_secret(bob_shared_secret)

    # Encrypt and decrypt test
    message = "This is a secret message!"
    print("[Original]:", message)

    ciphertext = aes_encrypt(message, alice_aes_key)
    print("[Encrypted by Alice]:", ciphertext)

    decrypted = aes_decrypt(ciphertext, bob_aes_key)
    print("[Decrypted by Bob]:", decrypted)
    
# class SecureSession:
#     def __init__(self, conn, is_initiator):
#         self.conn = conn
#         self.is_initiator = is_initiator
#         self.message_count = 0
#         self._generate_dh_keypair()
#         self._exchange_keys()

#     def _generate_dh_keypair(self):
#         self.dh_key = DSA.generate(2048)
#         self.public_key_bytes = self.dh_key.publickey().export_key()

#     def _exchange_keys(self):
#         if self.is_initiator:
#             self.conn.sendall(self.public_key_bytes)
#             their_pub_bytes = self.conn.recv(4096)
#         else:
#             their_pub_bytes = self.conn.recv(4096)
#             self.conn.sendall(self.public_key_bytes)

#         their_key = DSA.import_key(their_pub_bytes)
#         shared_secret = pow(their_key.y, self.dh_key.x, self.dh_key.p)
#         self.shared_key = derive_key_from_secret(str(shared_secret))
#         self.message_count = 0;

#     def _check_key_rotation(self):
#         if self.message_count >= MESSAGE_LIMIT:
#             self._generate_dh_keypair()
#             self._exchange_keys()

#     def encrypt_and_send(self, message: str):
#         self._check_key_rotation()
#         encrypted = aes_encrypt(message, self.shared_key)
#         self.conn.sendall(encrypted.encode() + b"\n")
#         self.message_count += 1

#     def receive_and_decrypt(self):
#         self._check_key_rotation()
#         encode = b""
#         while not encoded.endswith(b"\n"):
#             encoded += self.conn.recv(1024)

#         message = aes_decrypt(encoded.decode().strip(), self.shared_key)
#         self.message_count += 1
#         return message