import base64
import json
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA

"""""""""""""""""""""""""""
Cryptographic Utilities
"""""""""""""""""""""""""""


# Generate RSA Key pair
def create_rsa_key_pair() -> (bytes, bytes):
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return public_key, private_key


# Load RSA key from file
def load_rsa_key(file_path: str) -> bytes:
    try:
        with open(file_path, "rb") as f:
            return RSA.import_key(f.read()).export_key()
    except:
        return b''


# Save RSA key to file
def save_rsa_key(file_path: str, key: bytes) -> bool:
    try:
        with open(file_path, "wb") as f:
            f.write(key)
            return True
    except:
        return False


# Encrypt using RSA
def rsa_encrypt(data: bytes, pub_key) -> str:
    key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(data)).decode()


# Decrypt using RSA
def rsa_decrypt(data: bytes, prv_key) -> bytes:
    key = RSA.import_key(prv_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(data))


# Encrypt using AES
def aes_encrypt(data, hex_key) -> (str, str):
    key = bytes.fromhex(hex_key)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher_text = base64.b64encode(cipher.encrypt(data.encode())).decode()
    nonce = base64.b64encode(cipher.nonce).decode()
    return cipher_text, nonce


# Decrypt using AES
def aes_decrypt(encrypted, hex_key, nonce):
    key = bytes.fromhex(hex_key)
    nonce = base64.b64decode(nonce)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain_text = cipher.decrypt(base64.b64decode(encrypted.encode())).decode()
    return plain_text


# Derive a session key using HKDF
def create_session_key(master_key, salt=None, key_length=32):
    if salt is None:
        salt = os.urandom(16)  # Generate random salt if none provided

    derived_key = HKDF(master=master_key, salt=salt, key_len=key_length, hashmod=SHA256)
    return derived_key


# Create HMAC
def create_hmac(hex_key, message):
    h = HMAC.new(bytes.fromhex(hex_key), digestmod=SHA256)
    h.update(message.encode())
    return base64.b64encode(h.digest()).decode()


# Verify HMAC
def verify_hmac(hex_key, message, received_mac):
    h = HMAC.new(bytes.fromhex(hex_key), digestmod=SHA256)
    h.update(message.encode())
    try:
        h.verify(base64.b64decode(received_mac))
        return True
    except ValueError:
        return False


"""
File Utilities
"""


# Load dictionary from json file
def load_json_file(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {}


# Save dictionary into json file
def save_json_file(data, file_name: str, indent: int = 4):
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Error saving dict: {e}")
