import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

class Crypto():
    def __init__(self):
        self.BLOCK_SIZE = 16
        base_key = DSA.generate(2048)
        self.p = base_key.p
        self.q = base_key.q
        self.g = base_key.g

        self.key_private = int.from_bytes(os.urandom(32), 'big') % self.q
        self.key_public = pow(self.g, self.key_private, self.p)
    
    def derive_key(self, other_public: int) -> bytes:
        secret = pow(other_public, self.key_private, self.p)
        return SHA256.new(str(secret).encode()).digest()

    def aes_encrypt(self, message: str, key: bytes) -> str:
        iv = os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(message.encode(), self.BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self, encoded: str, key: bytes) -> str:
        try:
            combined = base64.b64decode(encoded)
            iv = combined[:self.BLOCK_SIZE]
            ciphertext = combined[self.BLOCK_SIZE:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)
            return decrypted.decode()
        except Exception as e:
            return f"[Decryption failed: {e}]"

if __name__ == "__main__":
    # Alice and Bob create their Crypto instances
    alice = Crypto()
    bob = Crypto()

    # Alice and Bob exchange public keys
    alice_shared_key = alice.derive_key(bob.key_public)
    bob_shared_key = bob.derive_key(alice.key_public)

    # Check if the derived keys match (they should)
    if alice_shared_key == bob_shared_key:
        print("[Test] Shared keys match: Success!")
    else:
        print("[Test] Shared keys do not match: Failure.")

    # Encrypt and decrypt message
    message = "This is a secret message!"
    print("[Original]:", message)

    ciphertext = alice.aes_encrypt(message, alice_shared_key)
    print("[Encrypted by Alice]:", ciphertext)

    decrypted = bob.aes_decrypt(ciphertext, bob_shared_key)
    print("[Decrypted by Bob]:", decrypted)