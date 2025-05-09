# secure_file_share.py

import os
import json
import time
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Key directories
KEY_DIR = "keys"
DATA_DIR = "data"
META_FILE = os.path.join(DATA_DIR, "file_meta.json")

os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# RSA Key Generation
def generate_rsa_keys(user):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(KEY_DIR, f"{user}_private.pem"), 'wb') as f:
        f.write(private_key)
    with open(os.path.join(KEY_DIR, f"{user}_public.pem"), 'wb') as f:
        f.write(public_key)

# File Encrpyption
def encrypt_file(input_file, sender, receiver, password, expire_seconds=10):
    # Load receiver's public key
    with open(os.path.join(KEY_DIR, f"{receiver}_public.pem"), 'rb') as f:
        receiver_key = RSA.import_key(f.read())

    # Generate AES key
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)

    # Encrypt file data
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(receiver_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Save encrypted file
    encrypted_file = os.path.join(DATA_DIR, "encrypted_file.bin")
    with open(encrypted_file, 'wb') as f:
        f.write(cipher_aes.nonce + tag + ciphertext)

    # Save metadata
    meta = {
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
        "password": password,
        "created_at": time.time(),
        "expire_seconds": expire_seconds,
        "failed_attempts": 0
    }

    # Encrypt metadata
    aes_key_meta = get_random_bytes(32)  # AES key for metadata encryption
    cipher_meta = AES.new(aes_key_meta, AES.MODE_EAX)
    meta_bytes = json.dumps(meta).encode()
    meta_ciphertext, meta_tag = cipher_meta.encrypt_and_digest(meta_bytes)

    # Save encrypted metadata
    with open(META_FILE, 'wb') as f:
        f.write(cipher_meta.nonce + meta_tag + meta_ciphertext)

    # Save the AES key for metadata encryption (secure this in production)
    with open(os.path.join(KEY_DIR, "meta_aes_key.bin"), 'wb') as f:
        f.write(aes_key_meta)

    print("File encrypted and metadata saved.")

# File Decryption
# ...existing code...

def decrypt_file(receiver, input_password):
    # Load the AES key for metadata decryption
    with open(os.path.join(KEY_DIR, "meta_aes_key.bin"), 'rb') as f:
        aes_key_meta = f.read()

    # Load and decrypt metadata
    with open(META_FILE, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_meta = AES.new(aes_key_meta, AES.MODE_EAX, nonce)
    try:
        meta_bytes = cipher_meta.decrypt_and_verify(ciphertext, tag)
        meta = json.loads(meta_bytes.decode())
    except ValueError:
        print("Metadata decryption failed. File may be tampered with.")
        return

    # Check if file expired
    expire_time = meta["created_at"] + meta["expire_seconds"]
    if time.time() > expire_time:
        print("File expired. Cannot decrypt.")
        return

    # Check password attempts
    if meta["failed_attempts"] >= 5:
        print("Too many failed attempts. Access locked.")
        return

    # Password check
    if input_password != meta["password"]:
        meta["failed_attempts"] += 1

        # Re-encrypt and save updated metadata
        cipher_meta = AES.new(aes_key_meta, AES.MODE_EAX)
        meta_bytes = json.dumps(meta).encode()
        meta_ciphertext, meta_tag = cipher_meta.encrypt_and_digest(meta_bytes)
        with open(META_FILE, 'wb') as f:
            f.write(cipher_meta.nonce + meta_tag + meta_ciphertext)

        print("Incorrect password.")
        return

    # Load receiver's private key
    with open(os.path.join(KEY_DIR, f"{receiver}_private.pem"), 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Decrypt AES key
    encrypted_key = base64.b64decode(meta["encrypted_key"])
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)

    # Load encrypted file
    encrypted_file = os.path.join(DATA_DIR, "encrypted_file.bin")
    with open(encrypted_file, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Save decrypted file
    with open(os.path.join(DATA_DIR, "decrypted_file.txt"), 'wb') as f:
        f.write(plaintext)

    print("File successfully decrypted.")

# ---------- Demo Usage ----------
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--genkeys', action='store_true')
    parser.add_argument('--encrypt', metavar='FILENAME')
    parser.add_argument('--decrypt', action='store_true')
    parser.add_argument('--user', type=str, default='userB')
    parser.add_argument('--password', type=str, default='secret')
    parser.add_argument('--expire', type=int, default=10)
    args = parser.parse_args()

    if args.genkeys:
        generate_rsa_keys("userA")
        generate_rsa_keys("userB")
    elif args.encrypt:
        encrypt_file(args.encrypt, "userA", args.user, args.password, args.expire)
    elif args.decrypt:
        decrypt_file(args.user, args.password)
