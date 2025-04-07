from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_public_key(public_key_path):
    with open(public_key_path, 'rb') as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_text(plaintext, public_key):
    return public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    # Get user input
    text_to_encrypt = input("Enter the text to encrypt: ")
    public_key_path = input("Enter the path to the public key (.pem): ")
    encrypted_filename = input("Enter the new encrypted filename (without the file extension): ")

    # Load public key
    try:
        public_key = load_public_key(public_key_path)
    except Exception as e:
        print(f"Failed to load public key: {e}")
        return

    # Encrypt the text
    try:
        encrypted_data = encrypt_text(text_to_encrypt, public_key)
    except Exception as e:
        print(f"Encryption failed: {e}")
        return

    # Create output filename
    output_file = encrypted_filename + ".dec"

    # Write encrypted data to file
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

    print(f"Encrypted data written to: {output_file}")

if __name__ == "__main__":
    main()