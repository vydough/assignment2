import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

SEPARATOR = "-" * 60

# Setting base variables for use in other OSes 
BASE = os.path.dirname(os.path.abspath(__file__))
# Setting directory names
OUTPUT_DIR = os.path.join(BASE, "output")
INPUT_DIR = os.path.join(BASE, "input")
KEYS_DIR = os.path.join(BASE, "keys")
# Setting input file for this task
INPUT_FILE = os.path.join(INPUT_DIR, "task2.txt")
# Setting path for keys
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, "rsa_private.pem")
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, "rsa_public.pem")
#Setting path for decryption/encryption
DECRYPTED_FILE = os.path.join(OUTPUT_DIR, "task2_decrypted.txt")
ENCRYPTED_FILE = os.path.join(OUTPUT_DIR, "task2_encrypted.bin")
ENCRYPTED_AES_KEY_FILE = os.path.join(OUTPUT_DIR, "aes_key_encrypted.bin")

# Makes directories if it doesnt exist
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# RSA KEY GENERATION
# Generating RSA keys into separate files
rsa_key = RSA.generate(2048)
# RSA Key pair generated with public and private key pair separately
# returns in bytes so opens the file in binary mode
with open(PRIVATE_KEY_FILE, "wb") as f:
    f.write(rsa_key.export_key())
with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(rsa_key.publickey().export_key())

# AES SYMMETRIC ENCRYPTION 
# Creates random one time use 128 bit key (session key) and reads it in raw bytes
# Files read in binary mode as AES works on raw bytes
aes_key = get_random_bytes(16)
with open(INPUT_FILE, "rb") as f:
    plaintext = f.read()

# AES encryption with EAX mode 
# EAX mode generates nonce so that encrypting the same file does not produce the same output
# Produce tag that works as tamper-detection checksum
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=get_random_bytes(16))     
ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

# Saving nonce + tag + ciophertex as one binary 
with open(ENCRYPTED_FILE, "wb") as f: 
    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(ciphertext)

# RSA ENCRYPTION
# Encrypt the AES session key with RSA-OAEP
# OAEP gives randomness to the raw RSA (not textbook RSA)
cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)

# Save RSA-encrypted AES key 
enc_aes_key = cipher_rsa.encrypt(aes_key)
with open (ENCRYPTED_AES_KEY_FILE, "wb") as f: 
    f.write(enc_aes_key)

# DECRYPTION
# Loading saved RSA private key 
with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = RSA.import_key(f.read())

# REad the encrypted AES Session key 
with open(ENCRYPTED_AES_KEY_FILE, 'rb') as f: 
    encrypted_session_key = f.read()

with open(ENCRYPTED_FILE, 'rb') as f: 
    encrypted_data = f.read()

#Extracting nonce, tag and ciphertext for verification ?
nonce = encrypted_data[:16]
saved_tag = encrypted_data[16:32]
saved_ciphertext = encrypted_data[32:]

# Using RSAprivate key to reverse RSA and recover AES key 
recovered_aes_key = PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(encrypted_session_key)
recovered_plaintext = AES.new(
    recovered_aes_key, AES.MODE_EAX, nonce=nonce
).decrypt_and_verify(saved_ciphertext, saved_tag)

# Saving the decrypted file
with open(DECRYPTED_FILE, "wb") as f:
    f.write(recovered_plaintext)

print(f"\n{SEPARATOR}")
print("\nRSA PRIVATE KEY:\n", rsa_key.export_key().decode())
print("\nRSA PUBLIC KEY:\n", rsa_key.publickey().export_key().decode())
print(f"\n{SEPARATOR}")
print("\nAES SESSION KEY (hex):\n", aes_key.hex())
print("\nAES NONCE (hex):", nonce.hex())
print("\nAUTHENTICAATION TAG (hex):\n", saved_tag.hex())
print("\nAES-ENCRYPTED FILE (hex):\n", saved_ciphertext.hex())
print(f"\n{SEPARATOR}")
print("\nRSA-ENCRYPTED AES KEY (hex):\n", enc_aes_key.hex())
print("\nDECRYPTED AES KEY (hex):\n", recovered_aes_key.hex())
print("\nDECRYPTED FILE CONTENT:\n", recovered_plaintext.decode())
print(f"\n{SEPARATOR}")
print("\nVerifying Successful Decryption:")
print("\nAES Key matches", aes_key == recovered_aes_key)
print("Ciphertext matches:", ciphertext == saved_ciphertext)
print("File matches:", plaintext == recovered_plaintext)
print(f"\n{SEPARATOR}")