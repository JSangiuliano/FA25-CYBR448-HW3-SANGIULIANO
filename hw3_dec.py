from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_private_key(path, password=None):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=password,
        )

def decrypt_data(encrypted_data, private_key):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def main():
    encrypted_path = input("Enter path to encrypted file (.dec): ").strip()
    private_key_path = input("Enter path to private key (.pem): ").strip()
    password_input = input("Enter private key password (leave empty if none): ").strip()
    password = password_input.encode() if password_input else None

    try:
        private_key = load_private_key(private_key_path, password)
    except Exception as e:
        print(f"Failed to load private key: {e}")
        return

    try:
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
    except Exception as e:
        print(f"Failed to read encrypted file: {e}")
        return

    try:
        decrypted_data = decrypt_data(encrypted_data, private_key)
        print("\nDecrypted Message:")
        print(decrypted_data.decode("utf-8"))
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
