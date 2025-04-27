import base64
import os
import socket
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256


class Crypto:

    def __init__(self):
        self.BLOCK_SIZE = 16
        base_key = DSA.generate(2048)
        self.p = base_key.p
        self.g = base_key.g

        self.key_private = int.from_bytes(os.urandom(32), 'big') % (self.p - 1)
        self.key_public = pow(self.g, self.key_private, self.p)

        self.key_shared = None

    def aes_encrypt(self,message: bytes) -> bytes:
        if self.key_shared is None:
            raise ValueError("Shared key has not been established.")
        iv = os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(self.key_shared, AES.MODE_CBC, iv)
        padded = pad(message, self.BLOCK_SIZE)

        ciphertext = cipher.encrypt(padded)

        return iv + ciphertext

    def aes_decrypt(self, encrypted: bytes) -> bytes:
        if self.key_shared is None:
            raise ValueError("Shared key has not been established.")
        iv = encrypted[:self.BLOCK_SIZE]
        ciphertext = encrypted[self.BLOCK_SIZE:]
        cipher = AES.new(self.key_shared, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)
        return decrypted
        
    def derive_key_from_secret(self, other_public: bytes) -> bytes:
        other_public_int = int.from_bytes(other_public, 'big')

        secret_int = pow(other_public_int, self.key_private, self.p)
        
        secret_bytes = secret_int.to_bytes((secret_int.bit_length() + 7) // 8, 'big')

        self.key_shared = SHA256.new(secret_bytes).digest()

        return self.key_shared
    
    def get_public_key_bytes(self) -> bytes:
        return self.key_public.to_bytes((self.key_public.bit_length() + 7) // 8, 'big')
    
    def test_keys(self):
        print(f"Private Key: {self.key_private}")
        print(f"Public Key: {self.key_public}")
        return self.key_private, self.key_public

if __name__ == "__main__":
    # User 1
        user1 = Crypto()
        user1_private, user1_public = user1.test_keys()
    
    # User 2
        user2 = Crypto()
        user2_private, user2_public = user2.test_keys()

        user1_public_bytes = user1.get_public_key_bytes()
        user2_public_bytes = user2.get_public_key_bytes()

    # Exchange public keys and derive the shared secret
        shared_key_user1 = user1.derive_key_from_secret(user2_public_bytes)
        shared_key_user2 = user2.derive_key_from_secret(user1_public_bytes)

    # Print the shared keys for both users
        print("Shared Key for User 1: ", shared_key_user1.hex())
        print("Shared Key for User 2: ", shared_key_user2.hex())

    # Verify if both users have the same shared key
        if shared_key_user1 == shared_key_user2:
            print("Success! Both users derived the same shared key.")
        else:
            print("Error! The shared keys are different.")
    
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