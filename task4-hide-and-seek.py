import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Establish a base path to make paths work on every OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Input, output and key directories
INPUT_DIR = os.path.join(BASE, "input")
KEYS_DIR = os.path.join(BASE, "keys")
OUTPUT_DIR = os.path.join(BASE, "output")

# Make directories if it doesn't already exist
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Constants for file paths
IMAGE = os.path.join(INPUT_DIR, "image.jpg")
AES_KEY = os.path.join(KEYS_DIR, "aes_key.bin")
STEGO_IMAGE = os.path.join(OUTPUT_DIR, "stego_image.jpg")
REVEALED_MESSAGE = os.path.join(OUTPUT_DIR, "task4_revealed_message.txt")

SEPARATOR = "-" * 60

# JPEG commen segement starts with these 2 marker bytes
# Anything inside these is ignored by image viewers
# This is good for hiding secret messages"
JPEG_MARKER = b"\xFF\xFE"

# Require the user to enter message to be hidden 
# Instead of hardcoding the message in the code
MESSAGE = input("Enter a message to be encoded into the image: ")
if MESSAGE == "":
    MESSAGE = "This is a secret message hidden inside the image using AES encryption and steganography."
    print("No message given, using the default message:\n", MESSAGE)

# ~~~~~~~~ ENCRYPTING THE MESSAGE WITH AES ~~~~~~~~ 
aes_key = get_random_bytes(16)
with open(AES_KEY, "wb") as f:
    f.write(aes_key)

# Encrypt the message using AES in CFB mode
cipher_aes = AES.new(aes_key, AES.MODE_CFB)
ciphertext = cipher_aes.encrypt(MESSAGE.encode())

# Combine IV and ciphertext into one payload
# Each component is 16 bytes, so no padding needed
payload = cipher_aes.iv + ciphertext

# HIDE ENCRYPTED TEXT INSIDE JPEG
with open(IMAGE, "rb") as f:
    image_bytes = f.read()

# Every JPEG file begins with 2-byte start of image marker 
marker = image_bytes[:2]

# Comment segment built using marker + 2-byte length
segment_length = len(payload) + 2 
comment_segement = JPEG_MARKER + segment_length.to_bytes(2, "big") + payload

# Insert comment segement after the 2-byte start of image marker
# Original image remains unchanged, but the comment segement is ignored by image viewers
stego_bytes = marker + comment_segement + image_bytes[2:]

with open(STEGO_IMAGE, "wb") as f:
    f.write(stego_bytes)

# ~~~~~~~~ EXTRACTING HIDDEN MESSAGE ~~~~~~~~ 
with open(STEGO_IMAGE, "rb") as f:
    stego_bytes_reloaded = f.read()

# Finding the comment marker to identify hidden message
marker_index = stego_bytes_reloaded.index(JPEG_MARKER)
length_bytes = stego_bytes_reloaded[marker_index + 2: marker_index + 4]
length = int.from_bytes(length_bytes, "big")
payload_start = marker_index + 4
payload_end = marker_index + 2 + length
hidden_payload = stego_bytes_reloaded[payload_start:payload_end]

# Splitting paylod into components
recovered_iv = hidden_payload[:16]
recovered_ciphertext = hidden_payload[16:]

# ~~~~~~~~ DECRYPTION USING AES KEY ~~~~~~~~ 
with open(AES_KEY, 'rb') as f:
    recovered_key = f.read()

recovered_message = AES.new(
    recovered_key, 
    AES.MODE_CFB, iv=recovered_iv
).decrypt(recovered_ciphertext)

with open(REVEALED_MESSAGE, "w") as f:
    f.write(recovered_message.decode())

print(SEPARATOR)
print("ORIGINAL MESSAGE:\n", MESSAGE)
print(SEPARATOR)
print("AES KEY (hex):\n", aes_key.hex())
print("\nENCRYPTED PAYLOAD HIDDEN IN IMAGE (hex):\n", ciphertext.hex())
print(SEPARATOR)
print("REVEALED MESSAGE (after extracting + decrypting):\n", recovered_message.decode())
print(SEPARATOR)