import os
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

def main():
    encrypted_image_folder = "encrypted_images"
    decrypted_image_folder = "decrypted_images"
    encrypted_text_folder = "encrypted_text_files"
    decrypted_text_folder = "decrypted_text_files"

    # Create folders if they don't exist
    for folder in [encrypted_image_folder, decrypted_image_folder, encrypted_text_folder, decrypted_text_folder]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    while True:
        choice = input("Would you like to work with 'image' or 'text' encryption, or 'exit' to quit: ").strip().lower()

        if choice == 'image':
            action = input("Would you like to 'encrypt' or 'decrypt' an image? ").strip().lower()
            password = input("Enter password: ")

            if action == 'encrypt':
                encryption_type = input("Choose encryption type ('fernet' or 'des'): ").strip().lower()
                file_path = input("Enter the path of the image file to encrypt: ")
                if os.path.exists(file_path):
                    if encryption_type == 'fernet':
                        encrypted_image = encrypt_image_fernet(file_path, password)
                    elif encryption_type == 'des':
                        encrypted_image = encrypt_image_des(file_path, password)
                    else:
                        print("Invalid encryption type.")
                        continue

                    save_option = input("Save the encrypted image to a file? (yes/no): ").strip().lower()
                    if save_option == 'yes':
                        file_name = input("Enter the name for the encrypted image file (without extension): ").strip()
                        encrypted_file_path = os.path.join(encrypted_image_folder, f"{file_name}.enc")
                        with open(encrypted_file_path, 'wb') as file:
                            file.write(encrypted_image)
                        print(f"Encrypted image saved to '{encrypted_file_path}'")

            elif action == 'decrypt':
                file_path = input("Enter the path of the encrypted image file: ")
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as file:
                        encrypted_image = file.read()

                    if encrypted_image.startswith(b"F:"):
                        decrypted_image = decrypt_image_fernet(encrypted_image[2:], password)
                    elif encrypted_image.startswith(b"D:"):
                        decrypted_image = decrypt_image_des(encrypted_image[2:], password)
                    else:
                        print("Unknown encryption format.")
                        continue

                    save_option = input("Save the decrypted image? (yes/no): ").strip().lower()
                    if save_option == 'yes':
                        file_name = input("Enter the name for the decrypted image (e.g., output_image.png): ").strip()
                        decrypted_file_path = os.path.join(decrypted_image_folder, file_name)
                        with open(decrypted_file_path, 'wb') as file:
                            file.write(decrypted_image)
                        print(f"Decrypted image saved to '{decrypted_file_path}'")

        elif choice == 'text':
            action = input("Would you like to 'encrypt' or 'decrypt' a text message? ").strip().lower()
            password = input("Enter password: ")

            if action == 'encrypt':
                encryption_type = input("Choose encryption type ('fernet' or 'des'): ").strip().lower()
                method = input("Encrypt a 'message' or a 'file'? ").strip().lower()

                if method == 'message':
                    message = input("Enter the message to encrypt: ")
                    if encryption_type == 'fernet':
                        encrypted_message = encrypt_message_fernet(message, password)
                    elif encryption_type == 'des':
                        encrypted_message = encrypt_message_des(message, password)
                    else:
                        print("Invalid encryption type.")
                        continue

                    print("Encrypted message:", encrypted_message.decode('utf-8', errors='ignore'))
                    save_option = input("Save the encrypted message to a file? (yes/no): ").strip().lower()
                    if save_option == 'yes':
                        file_name = input("Enter the name for the encrypted message file (without extension): ").strip()
                        file_path = os.path.join(encrypted_text_folder, f"{file_name}.txt")
                        with open(file_path, 'wb') as file:
                            file.write(encrypted_message)
                        print(f"Encrypted message saved to '{file_path}'")

                elif method == 'file':
                    file_path = input("Enter the path of the file to encrypt: ")
                    if os.path.exists(file_path):
                        with open(file_path, 'r') as file:
                            message = file.read()
                        if encryption_type == 'fernet':
                            encrypted_message = encrypt_message_fernet(message, password)
                        elif encryption_type == 'des':
                            encrypted_message = encrypt_message_des(message, password)
                        else:
                            print("Invalid encryption type.")
                            continue

                        save_option = input("Save the encrypted message to a file? (yes/no): ").strip().lower()
                        if save_option == 'yes':
                            file_name = input("Enter the name for the encrypted message file (without extension): ").strip()
                            file_path = os.path.join(encrypted_text_folder, f"{file_name}.txt")
                            with open(file_path, 'wb') as file:
                                file.write(encrypted_message)
                            print(f"Encrypted message saved to '{file_path}'")

            elif action == 'decrypt':
                method = input("Decrypt a 'message' or a 'file'? ").strip().lower()
                if method == 'message':
                    encrypted_message = input("Enter the encrypted message: ").encode()

                elif method == 'file':
                    file_path = input("Enter the path of the file with the encrypted message: ")
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as file:
                            encrypted_message = file.read()
                    else:
                        print("File not found.")
                        continue

                if encrypted_message.startswith(b"F:"):
                    decrypted_message = decrypt_message_fernet(encrypted_message[2:], password)
                elif encrypted_message.startswith(b"D:"):
                    decrypted_message = decrypt_message_des(encrypted_message[2:], password)
                else:
                    print("Unknown encryption format.")
                    continue

                print("Decrypted message:", decrypted_message)
                save_option = input("Save the decrypted message to a file? (yes/no): ").strip().lower()
                if save_option == 'yes':
                    file_name = input("Enter the name for the decrypted message file (without extension): ").strip()
                    file_path = os.path.join(decrypted_text_folder, f"{file_name}.txt")
                    with open(file_path, 'w') as file:
                        file.write(decrypted_message)
                    print(f"Decrypted message saved to '{file_path}'")

        elif choice == 'exit':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
