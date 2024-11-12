import tkinter as tk
from tkinter import filedialog, messagebox, Text
from encryption.image_encryption import (
    encrypt_image_fernet,
    decrypt_image_fernet,
    encrypt_image_des,
    decrypt_image_des,
)
from encryption.text_encryption import (
    encrypt_message_fernet,
    decrypt_message_fernet,
    encrypt_message_des,
    decrypt_message_des,
)
import os

# Set up directories for encrypted and decrypted files
encrypted_image_folder = "encrypted_images"
decrypted_image_folder = "decrypted_images"
encrypted_text_folder = "encrypted_text_files"
decrypted_text_folder = "decrypted_text_files"

for folder in [encrypted_image_folder, decrypted_image_folder, encrypted_text_folder, decrypted_text_folder]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Functions for encryption and decryption
def encrypt_text():
    password = password_entry.get()
    message = text_input.get("1.0", tk.END).strip()
    encryption_type = encryption_type_var.get()

    if not message or not password:
        messagebox.showerror("Error", "Please provide both message and password.")
        return

    try:
        if encryption_type == 'fernet':
            encrypted_message = encrypt_message_fernet(message, password)
        elif encryption_type == 'des':
            encrypted_message = encrypt_message_des(message, password)
        else:
            messagebox.showerror("Error", "Invalid encryption type.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted_message.decode('utf-8', errors='ignore'))
        
        save_encrypted_text(encrypted_message)
        messagebox.showinfo("Success", "Text encrypted and saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_text():
    password = password_entry.get()
    encrypted_message = text_input.get("1.0", tk.END).strip().encode()
    
    if not encrypted_message or not password:
        messagebox.showerror("Error", "Please provide both encrypted message and password.")
        return

    try:
        if encrypted_message.startswith(b"F:"):
            decrypted_message = decrypt_message_fernet(encrypted_message[2:], password)
        elif encrypted_message.startswith(b"D:"):
            decrypted_message = decrypt_message_des(encrypted_message[2:], password)
        else:
            messagebox.showerror("Error", "Unknown encryption format.")
            return

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_message)

        save_decrypted_text(decrypted_message)
        messagebox.showinfo("Success", "Text decrypted and saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt_image():
    password = password_entry.get()
    encryption_type = encryption_type_var.get()
    file_path = filedialog.askopenfilename(title="Select Image")

    if not file_path or not password:
        messagebox.showerror("Error", "Please select an image and provide a password.")
        return

    try:
        if encryption_type == 'fernet':
            encrypted_image = encrypt_image_fernet(file_path, password)
        elif encryption_type == 'des':
            encrypted_image = encrypt_image_des(file_path, password)
        else:
            messagebox.showerror("Error", "Invalid encryption type.")
            return

        save_encrypted_image(encrypted_image)
        messagebox.showinfo("Success", "Image encrypted and saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_image():
    password = password_entry.get()
    file_path = filedialog.askopenfilename(title="Select Encrypted Image")

    if not file_path or not password:
        messagebox.showerror("Error", "Please select an encrypted image and provide a password.")
        return

    try:
        with open(file_path, 'rb') as file:
            encrypted_image = file.read()

        if encrypted_image.startswith(b"F:"):
            decrypted_image = decrypt_image_fernet(encrypted_image[2:], password)
        elif encrypted_image.startswith(b"D:"):
            decrypted_image = decrypt_image_des(encrypted_image[2:], password)
        else:
            messagebox.showerror("Error", "Unknown encryption format.")
            return

        save_decrypted_image(decrypted_image)
        messagebox.showinfo("Success", "Image decrypted and saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# File saving functions
def save_encrypted_text(encrypted_message):
    file_path = os.path.join(encrypted_text_folder, "encrypted_message.txt")
    with open(file_path, 'wb') as file:
        file.write(encrypted_message)

def save_decrypted_text(decrypted_message):
    file_path = os.path.join(decrypted_text_folder, "decrypted_message.txt")
    with open(file_path, 'w') as file:
        file.write(decrypted_message)

def save_encrypted_image(encrypted_image):
    file_path = os.path.join(encrypted_image_folder, "encrypted_image.enc")
    with open(file_path, 'wb') as file:
        file.write(encrypted_image)

def save_decrypted_image(decrypted_image):
    file_path = os.path.join(decrypted_image_folder, "decrypted_image.png")
    with open(file_path, 'wb') as file:
        file.write(decrypted_image)

# GUI setup
root = tk.Tk()
root.title("Encryption and Decryption Tool")

# Encryption type selection
encryption_type_var = tk.StringVar(value='fernet')
tk.Label(root, text="Encryption Type:").pack()
tk.Radiobutton(root, text="Fernet", variable=encryption_type_var, value='fernet').pack()
tk.Radiobutton(root, text="DES", variable=encryption_type_var, value='des').pack()

# Password entry
tk.Label(root, text="Password:").pack()
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

# Text input/output
tk.Label(root, text="Input Text / Encrypted Message:").pack()
text_input = Text(root, height=6, width=50)
text_input.pack()

# Buttons for text encryption and decryption
tk.Button(root, text="Encrypt Text", command=encrypt_text).pack()
tk.Button(root, text="Decrypt Text", command=decrypt_text).pack()

# Output display for encrypted or decrypted text
tk.Label(root, text="Output:").pack()
output_text = Text(root, height=6, width=50)
output_text.pack()

# Image encryption and decryption buttons
tk.Button(root, text="Encrypt Image", command=encrypt_image).pack()
tk.Button(root, text="Decrypt Image", command=decrypt_image).pack()

# Run the application
root.mainloop()
