import base64
import os
import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

class Crypto():
    def __init__(self, pqg = None): 
        self.block_size = 16

        if pqg == None: 
            base_key = DSA.generate(1024)

            self.p = base_key.p
            self.q = base_key.q
            self.g = base_key.g
        else:
            self.p = pqg[0]
            self.q = pqg[1]
            self.g = pqg[2]

        self.key_private = int.from_bytes(os.urandom(32), 'big') % self.q
        self.key_public = pow(self.g, self.key_private, self.p)

        self.key_shared = None

    def derive_shared_key(self,other_public):
        secret = pow(other_public, self.key_private, self.p)
        self.key_shared = SHA256.new(str(secret).encode()).digest()

    def aes_encrypt(self, message: bytes) -> bytes:
        iv = os.urandom(self.block_size)  # Generate a random initialization vector (IV)
        cipher = AES.new(self.key_shared, AES.MODE_CBC, iv)
        padded = pad(message, self.block_size)  # Pad message to be a multiple of block_size
        ciphertext = cipher.encrypt(padded)
        # Return the concatenated IV and ciphertext as bytes
        return iv + ciphertext

    def aes_decrypt(self, encoded: bytes) -> bytes:
        try:
            iv = encoded[:self.block_size]  # Extract the IV from the first part of the input
            ciphertext = encoded[self.block_size:]  # The rest is the ciphertext
            cipher = AES.new(self.key_shared, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), self.block_size)  # Unpad after decryption
            return decrypted  # Return the decrypted data as bytes
        except Exception as e:
            raise ValueError(f"[Decryption failed: {e}]")


if __name__ == "__main__":
    # Generate base parameters
    base_key = DSA.generate(2048)

    # Initialize Alice and Bob with the same base key
    alice = Crypto(base_key)
    bob = Crypto(base_key)

    # Derive shared keys
    alice_shared_key = alice.derive_shared_key(bob.key_public)
    bob_shared_key = bob.derive_shared_key(alice.key_public)

    # Test shared key equality
    assert alice_shared_key == bob_shared_key, "Shared keys do not match!"
    print("[+] Shared key test passed.")

    # Test encryption/decryption from Alice to Bob
    message = "Hello Bob, it's Alice!"
    print(f"[+] Original message: {message}")

    encrypted_msg = alice.aes_encrypt(message, alice_shared_key)
    print(f"[+] Encrypted message: {encrypted_msg}")

    decrypted_msg = bob.aes_decrypt(encrypted_msg, bob_shared_key)
    print(f"[+] Decrypted message (Bob): {decrypted_msg}")

    assert decrypted_msg == message, "Decryption failed! Messages do not match."
    print("[+] Encryption/Decryption test (Alice -> Bob) passed.")

    # Test encryption/decryption from Bob to Alice
    reply = "Hi Alice, Bob here!"
    print(f"[+] Original reply: {reply}")

    encrypted_reply = bob.aes_encrypt(reply, bob_shared_key)
    print(f"[+] Encrypted reply: {encrypted_reply}")

    decrypted_reply = alice.aes_decrypt(encrypted_reply, alice_shared_key)
    print(f"[+] Decrypted reply (Alice): {decrypted_reply}")

    assert decrypted_reply == reply, "Decryption failed! Replies do not match."
    print("[+] Encryption/Decryption test (Bob -> Alice) passed.")
