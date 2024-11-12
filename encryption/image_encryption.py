from cryptography.fernet import Fernet
from Crypto.Cipher import DES
import hashlib
import base64

# Generate a 32-byte Base64 encoded key for Fernet from the user's given key
def create_key_from_password(password):
    hashed_password = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed_password)

# Encrypt image with Fernet
def encrypt_image_fernet(image_path, password):
    key = create_key_from_password(password)
    cipher = Fernet(key)

    # Read image binary data
    with open(image_path, 'rb') as file:
        image_data = file.read()

    # Encrypt image data
    encrypted_data = cipher.encrypt(image_data)
    return b"F:" + encrypted_data


# Decrypt image with Fernet
def decrypt_image_fernet(encrypted_data, password):
    key = create_key_from_password(password)
    cipher = Fernet(key)


    # Decrypt image data
    decrypted_data = cipher.decrypt(encrypted_data)
    
    return decrypted_data

# Generate an 8-byte key for DES
def create_des_key_from_password(password):
    return hashlib.md5(password.encode()).digest()[:8]

# Pad data to be a multiple of 8 bytes for DES
def pad(data):
    padding_len = 8 - (len(data) % 8)
    return data + (b' ' * padding_len)

# Remove padding for DES
def unpad(data):
    return data.rstrip(b' ')

# Encrypt image with DES
def encrypt_image_des(image_path, password):
    key = create_des_key_from_password(password)
    des = DES.new(key, DES.MODE_ECB)

    # Read image binary data
    with open(image_path, 'rb') as file:
        image_data = file.read()

    # Pad image data for DES encryption
    padded_data = pad(image_data)
    
    # Encrypt image data
    encrypted_data = des.encrypt(padded_data)

    return b"D:" + encrypted_data

# Decrypt image with DES
def decrypt_image_des(encrypted_data, password):
    key = create_des_key_from_password(password)
    des = DES.new(key, DES.MODE_ECB)
    
    # Decrypt image data
    decrypted_data = des.decrypt(encrypted_data)
    
    # Unpad data after decryption
    unpadded_data = unpad(decrypted_data)

    return unpadded_data
