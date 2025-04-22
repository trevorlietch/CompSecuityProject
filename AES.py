import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

def aes_encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(salt + iv + ciphertext).decode()

def aes_decrypt(encoded: str, password: str) -> str:
    try:
        combined = base64.b64decode(encoded)
        salt = combined[:16]
        iv = combined[16:32]
        ciphertext = combined[32:]
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
        return decrypted.decode()
    except Exception as e:
        return f"[Decryption failed: {e}]"