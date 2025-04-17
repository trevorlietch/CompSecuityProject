import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Constants
BLOCK_SIZE = 16        # AES block size
KEY_LENGTH = 32        # AES-256 = 32 bytes
PBKDF2_ITERATIONS = 100_000

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

# AES encryption
def aes_encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)

    combined = salt + iv + ciphertext
    return base64.b64encode(combined).decode()

# AES decryption
def aes_decrypt(encoded: str, password: str) -> str:
    combined = base64.b64decode(encoded)
    salt = combined[:16]
    iv = combined[16:32]
    ciphertext = combined[32:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    return decrypted.decode()

# Test it
if __name__ == "__main__":
    password = "sharedSecret123"
    message = input("Enter a message to encrypt: ")

    encrypted = aes_encrypt(message, password)
    print(f"\n🔒 Encrypted (base64):\n{encrypted}")

    decrypted = aes_decrypt(encrypted, password)
    print(f"\n🔓 Decrypted:\n{decrypted}")
