from cryptography.fernet import Fernet
from Crypto.Cipher import DES
import hashlib
import base64

# Generate a 32-byte Base64 encoded key for Fernet from the user's given key
def create_key_from_password(password):
    hashed_password = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed_password)

# Encrypt message with Fernet
def encrypt_message_fernet(message, password):
    key = create_key_from_password(password)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return b"F:" + encrypted_message  # Prefix to identify Fernet encryption

# Decrypt message with Fernet
def decrypt_message_fernet(encrypted_message, password):
    key = create_key_from_password(password)
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

def pad(text):
    # Pad with spaces up to the nearest 8-byte multiple
    padding_len = 8 - (len(text) % 8)
    return text + (chr(padding_len) * padding_len)

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# Generate an 8-byte key for DES
def create_des_key_from_password(password):
    return hashlib.md5(password.encode()).digest()[:8]

# Encrypt message with DES
def encrypt_message_des(message, password):
    key = create_des_key_from_password(password)
    des = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message)
    encrypted_message = des.encrypt(padded_message.encode())
    return b"D:" + base64.b64encode(encrypted_message)  # Prefix to identify DES encryption

# Decrypt message with DES
def decrypt_message_des(encrypted_message, password):
    key = create_des_key_from_password(password)
    des = DES.new(key, DES.MODE_ECB)
    encrypted_message= base64.b64decode(encrypted_message)
    decrypted_message = des.decrypt(encrypted_message).decode()
    unpadded_message= unpad(decrypted_message)
    return unpadded_message

