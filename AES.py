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
    return SHA256.new(str(secret).encode()).digest()

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
    
# Diffie-Hellman key exchange setup
base_key = DSA.generate(2048)
p = base_key.p
q = base_key.q
g = base_key.g

# Generate Alice's key pair with shared params
alice_private = int.from_bytes(os.urandom(32), 'big') % q
alice_public = pow(g, alice_private, p)

# Generate Bob's key pair with shared params
bob_private = int.from_bytes(os.urandom(32), 'big') % q
bob_public = pow(g, bob_private, p)

# Exchange public keys and compute shared secrets
alice_shared_secret = pow(bob_public, alice_private, p)
bob_shared_secret = pow(alice_public, bob_private, p)

# Derive AES keys
alice_aes_key = derive_key_from_secret(alice_shared_secret)
bob_aes_key = derive_key_from_secret(bob_shared_secret)

# Verify that Alice's and Bob's derived keys are the same
def test_shared_key():
    if alice_aes_key == bob_aes_key:
        print("[Test] Shared keys match: Success!")
    else:
        print("[Test] Shared keys do not match: Failure.")

# Encrypt and decrypt test
message = "This is a secret message!"
print("[Original]:", message)

ciphertext = aes_encrypt(message, alice_aes_key)
print("[Encrypted by Alice]:", ciphertext)

decrypted = aes_decrypt(ciphertext, bob_aes_key)
print("[Decrypted by Bob]:", decrypted)

# Run the shared key test
test_shared_key()