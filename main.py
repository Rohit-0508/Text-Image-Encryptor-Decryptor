from cryptography.fernet import Fernet
import hashlib
import base64
import os

# Generating a 32-byte Base64 based encoded key from the user's given key

def create_key_from_password(password):
    
    hashed_password = hashlib.sha256(password.encode()).digest();
    return base64.urlsafe_b64encode(hashed_password) # converting to Base64 for Fernet


# Encrypting a message with a user provided password

def encrypt_message(message, password):
    key= create_key_from_password(password) 
    cipher= Fernet(key)
    encrypted_message= cipher.encrypt(message.encode())
    return encrypted_message

# Decrypting a message with user provided password

def decrypt_message(encrypted_message, password):
    key= create_key_from_password(password)
    cipher= Fernet(key)
    decrypted_message= cipher.decrypt(encrypted_message).decode()
    return decrypted_message

def main():
    encrypted_folder= "encrypted_files"
    if not os.path.exists(encrypted_folder):
        os.makedirs(encrypted_folder)

    while True:
        choice = input("Would you like to encrypt or decrypt a message? (type 'encrypt' or 'decrypt', or 'exit' to quit): ").strip().lower()

        if choice == 'encrypt':
            password = input("Enter password for encryption: ")
            method = input("Would you like to enter a message or encrypt a file? (type 'message' or 'file'): ").strip().lower()

            if method == 'message':
                message = input("Enter the message to encrypt: ")
                encrypted_message = encrypt_message(message, password)
                print("Encrypted message:", encrypted_message.decode())

                save_option = input("Would you like to save the encrypted message to a file? (yes/no): ").strip().lower()
                if save_option == 'yes':
                    while True:
                        file_name = input("Enter the name for the encrypted message file (without extension): ").strip()
                        file_path = os.path.join(encrypted_folder, f"{file_name}.txt")

                        # Check if the file already exists
                        if os.path.exists(file_path):
                            print(f"The file '{file_path}' already exists. Please choose a different name.")
                        else:
                            with open(file_path, 'wb') as file:
                                file.write(encrypted_message)
                            print(f"Encrypted message saved to '{file_path}'")
                            break  # Exit the loop if the file is successfully saved

            elif method == 'file':
                file_path = input("Enter the path of the file to encrypt: ")
                if os.path.exists(file_path):
                    with open(file_path, 'r') as file:
                        message = file.read()
                    encrypted_message = encrypt_message(message, password)
                    print("Encrypted message:", encrypted_message.decode())

                    save_option = input("Would you like to save the encrypted message to a file? (yes/no): ").strip().lower()
                    if save_option == 'yes':
                        while True:
                            file_name = input("Enter the name for the encrypted message file (without extension): ").strip()
                            encrypted_file_path = os.path.join(encrypted_folder, f"{file_name}.txt")

                            # Check if the file already exists
                            if os.path.exists(encrypted_file_path):
                                print(f"The file '{encrypted_file_path}' already exists. Please choose a different name.")
                            else:
                                with open(encrypted_file_path, 'wb') as file:
                                    file.write(encrypted_message)
                                print(f"Encrypted message saved to '{encrypted_file_path}'")
                                break  # Exit the loop if the file is successfully saved
                else:
                    print("File not found. Please check the path.")

        elif choice == 'decrypt':
            password = input("Enter password for decryption: ")
            method = input("Would you like to enter the encrypted message or decrypt a file? (type 'message' or 'file'): ").strip().lower()

            if method == 'message':
                encrypted_message = input("Enter the encrypted message: ").strip()
                try:
                    encrypted_message_bytes = encrypted_message.encode()  # Convert string to bytes
                    decrypted = decrypt_message(encrypted_message_bytes, password)
                    print("Decrypted message:", decrypted)
                except Exception as e:
                    print("Decryption failed. Incorrect password or corrupted message.")

            elif method == 'file':
                file_path = input("Enter the path of the file with the encrypted message: ")
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as file:
                        encrypted_message = file.read()
                    try:
                        decrypted = decrypt_message(encrypted_message, password)
                        print("Decrypted message:", decrypted)
                    except Exception as e:
                        print("Decryption failed. Incorrect password or corrupted message.")
                else:
                    print("File not found. Please check the path.")

        elif choice == 'exit':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

#Example usage
# if __name__ == "__main__":
#     password= input("Enter password for Encryption: ")
#     message= input("Enter the message to encrypt: ")

#     encrypted= encrypt_message(message, password)
#     print("Encrypted message: ", encrypted)


#     password_for_decryption= input("Enter the password for decryption: ")
#     try:
#         decrypted= decrypt_message(encrypted, password_for_decryption)
#         print("Decrypted message: ", decrypted)
#     except Exception as e:
#         print("Decryption failed. Incorrect password or corrupted message.")