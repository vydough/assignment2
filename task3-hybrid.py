import os
# Import necessary modules from pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes

SEPARATOR = "-" * 60

# Base Directory for portable file paths 
# Based on L4, L5 code archive examples
BASE = os.path.dirname(os.path.abspath(__file__))

# Input, output and key directories
OUTPUT_DIR = os.path.join(BASE, "output")
INPUT_DIR = os.path.join(BASE, "input")
KEYS_DIR = os.path.join(BASE, "keys")

# Input plaintext file 
INPUT_FILE = os.path.join(INPUT_DIR, "task2.txt")

# RSA key files 
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "rsa_private.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "rsa_public.pem")

# Encrypted and decryted output files
DECRYPTED_FILE = os.path.join(OUTPUT_DIR, "task2_decrypted.txt")
ENCRYPTED_FILE = os.path.join(OUTPUT_DIR, "task2_encrypted.bin")
ENCRYPTED_AES_KEY_FILE = os.path.join(OUTPUT_DIR, "aes_key_encrypted.bin")

# Creates directories if they don't exist
# Structure is based on Lectorial 5 code archive examples 
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# ~~~~~~~~~~ RSA KEY GENERATION ~~~~~~~~~~
# Generating RSA keys into separate files
# Code based on Lectorial 5 code archive examples
def generate_rsa_keys():
    # Generate 2048-bit RSA key pair 
    rsa_key = RSA.generate(2048)

    # Saving private key 
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(rsa_key.export_key())

    # Saving the associated public key 
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(rsa_key.publickey().export_key())

    # Displays the keys to output
    print(f"\n{SEPARATOR}")
    print("\nRSA PRIVATE KEY:\n")
    print(rsa_key.export_key().decode())
    print("\nRSA PUBLIC KEY:\n")
    print(rsa_key.publickey().export_key())

def sender_encrypt():
    # Load key files in binary mode to read the raw bytes for AES and RSA encryption
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = RSA.import_key(f.read())
    # read plaintext as raw bytes
    with open(INPUT_FILE, "rb") as f:
        plaintext = f.read()

    # ~~~~~~~~~~ AES SYMMETRIC ENCRYPTION ~~~~~~~~~~ 
    # Creates random one time use 128 bit key (session key)
    aes_key = get_random_bytes(16) 

    # AES-CFB Encryption Mode chosen
    # Code is based on Lectorial 5 code arhive
    # Does not produce authentication tag for tamper detection

    # Encrypt plaintext using AEs in CFB mode
    # CFB does not require padding, uses randomly generated IV: cipher_aes.iv
    cipher_aes = AES.new(aes_key, AES.MODE_CFB)
    ciphertext = cipher_aes.encrypt(plaintext)

    # Saving encrypted file with IV + Ciphertext
    with open(ENCRYPTED_FILE, "wb") as f: 
        f.write(cipher_aes.iv)
        f.write(ciphertext)

    # RSA-OAEP ENCRYPTION (asymmetric encryption)
    # Encrypt the AES session key with RSA-OAEP
    # OAEP adds randomised padding to the raw RSA (not textbook RSA)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Save RSA-encrypted AES session key
    with open (ENCRYPTED_AES_KEY_FILE, "wb") as f: 
        f.write(encrypted_aes_key)

    # Displays key and encrypted files to output
    print(f"\n{SEPARATOR}")
    print("Sender performs AES and RSA Encryption")
    print("\nAES SESSION KEY (hex):\n", aes_key)
    print("\nAES-ENCRYPTED FILE (hex):\n", ciphertext.hex())
    print("\nRSA-ENCRYPTED FILE (hex):\n", encrypted_aes_key.hex())
    
    # Return the original key for verification
    return aes_key

def receiver_decrypt():
    # ~~~~~~~~~ DECRYPTION ~~~~~~~~~
    # Loading saved RSA private key used to recover the AES session key
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Read the RSA-Encrypted AES Session key 
    with open(ENCRYPTED_AES_KEY_FILE, 'rb') as f: 
        encrypted_aes_key = f.read()

    # Read the stored IV + Ciphertext
    with open(ENCRYPTED_FILE, 'rb') as f: 
        encrypted_data = f.read()

    # Extracting the first 16 bytes is AES IV
    iv = encrypted_data[:16]
    # Extracting the remaining bytes is AES ciphertext
    ciphertext = encrypted_data[16:]

    # Recover the AES session key using RSA private key 
    recovered_aes_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_aes_key)
    
    # Rebuild AES using the same key and IV as before
    # Reversing the encryption using decrypt()
    # CFB does not have verify step after decryption - no authentication provided
    recovered_plaintext = AES.new(
        recovered_aes_key, 
        AES.MODE_CFB, 
        iv=iv
    ).decrypt(ciphertext)

    # Saving the recovered plaintext
    with open(DECRYPTED_FILE, "wb") as f:
        f.write(recovered_plaintext) 

    # Displays the decrypted output
    print(f"\n{SEPARATOR}")
    print("Receiver performs RSA and AES Decryption")
    print("\nDECRYPTED AES KEY (hex):\n", recovered_aes_key.hex())
    print("\nDECRYPTED FILE CONTENT:\n", recovered_plaintext.decode())

    return recovered_aes_key

def verify_results(original_aes_key, recovered_aes_key):
    # Read the original plaintext
    with open(INPUT_FILE, "rb") as f:
        plaintext = f.read()

    # Read the recovered plaintext
    with open(DECRYPTED_FILE, "rb") as f: 
        recovered_plaintext = f.read()

    # Compare the original and recovered AES keys and plaintext from task2.txt
    print(f"\n{SEPARATOR}")
    print("\nVerifying Successful Decryption:")
    print("\nAES Key matches", original_aes_key == recovered_aes_key)
    print("File matches:", plaintext == recovered_plaintext)

# Main function for implemnentation 
def main():
    generate_rsa_keys()
    original_aes_key = sender_encrypt()
    recovered_aes_key = receiver_decrypt()
    verify_results(original_aes_key, recovered_aes_key)

if __name__ == "__main__":
    main()