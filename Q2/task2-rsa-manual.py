import os

# I used the following code references from the course:
# I used Lectorial 5's rsa_file.py as a reference for the RSA program structure and file handling.
# I also used Week 6 Practical's rsa_padding_file.py as a reference for the RSA encryption and decryption process.
# I implemented the RSA calculations in this program manually without the use of any cryptographic libraries. 

# Making sure the paths work on all operating systems
BASE = os.path.dirname(os.path.abspath(__file__))

# Checking if a number is prime
def is_prime(number):
    if number < 2:
        return False
    
    # Checking for factors up to the square root of the number
    for i in range(2, int(number ** 0.5) + 1):
        if number % i == 0:
            return False

    return True

# Asking the user to enter a prime number
def get_prime(name):
    while True:
        number = int(input(f"Please enter a prime number {name} (at least 5 digits): "))

        # Checking that the number has at least 5 digits and is prime
        if number < 10000:
            print("Your prime number must be at least 5 digits!")
        elif not is_prime(number):
            print("Your number is not a prime number!")
        else:
            return number

# Finding the greatest common divisor (gcd)
def gcd(a, b):
    # Using the Euclidean algorithm
    while b != 0:
        a, b = b, a % b

    return a

# Finding the modular inverse
def mod_inverse(e, phi):
    # Using the Extended Euclidean Algorithm
    old_r, r = e, phi
    old_s, s = 1, 0
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    return old_s % phi

# Generating the RSA public and private keys
def generate_keys():
    # Getting the two prime numbers
    p = get_prime("p")
    q = get_prime("q")

    # Making sure p and q are different prime numbers
    while q == p:
        print("p and q must be different prime numbers!")
        q = get_prime("q")

    # Calculating n and Euler's totient
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choosing e
    e = 65537

    # If 65537 cannot be used, find another value for e
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    # Calculating the private exponent d
    d = mod_inverse(e, phi)
    # Creating the public and private keys
    public_key = (e, n)
    private_key = (d, n)
    # Displaying the RSA calculations
    print("\nRSA key calculations:")
    print("p =", p)
    print("q =", q)
    print("n =", n)
    print("phi(n) =", phi)
    print("e =", e)
    print("d =", d)

    return public_key, private_key

# Reading the student number from the input file 
def read_file():
    # Creating the path to the input file using BASE
    input_file = os.path.join(BASE, "input", "student_number.txt")
    # Reading the student number from the file
    with open(input_file, "r") as file:
        message = file.read().strip()

    return message

# Encrypting the message using the public key
def encrypt_message(message, public_key):
    e, n = public_key
    encrypted_message = []

    for character in message:
        # Converting each character to a number and encrypting it
        m = ord(character)
        c = pow(m, e, n)
        encrypted_message.append(c)

    return encrypted_message

# Decrypting the message using the private key
def decrypt_message(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = ""

    for c in encrypted_message:
        # Decrypting each value and converting it back to a character
        m = pow(c, d, n)
        decrypted_message += chr(m)

    return decrypted_message

# Saving the public and private keys
def save_keys(public_key, private_key):
    # Creating the paths for the key files using BASE
    public_key_file = os.path.join(BASE, "keys", "public_key.txt")
    private_key_file = os.path.join(BASE, "keys", "private_key.txt")
    # Saving the public key
    with open(public_key_file, "w") as file:
        file.write(str(public_key))
    # Saving the private key
    with open(private_key_file, "w") as file:
        file.write(str(private_key))


# Saving the encrypted and decrypted messages
def save_messages(encrypted_message, decrypted_message):
    # Creating the paths for the output files using BASE
    encrypted_file = os.path.join(BASE, "output", "encrypted.txt")
    decrypted_file = os.path.join(BASE, "output", "decrypted.txt")
    # Saving the encrypted message
    with open(encrypted_file, "w") as file:
        file.write(" ".join(str(c) for c in encrypted_message))
    # Saving the decrypted message
    with open(decrypted_file, "w") as file:
        file.write(decrypted_message)

# Running the RSA program
def main():
    # Generating the RSA keys
    public_key, private_key = generate_keys()

    # Reading the student number
    message = read_file()

    # Encrypting and decrypting the student number
    encrypted_message = encrypt_message(message, public_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)

    # Saving the keys and messages
    save_keys(public_key, private_key)
    save_messages(encrypted_message, decrypted_message)

    # Displaying the results
    print("\nOriginal message:", message)
    print("Encrypted message:", encrypted_message)
    print("Decrypted message:", decrypted_message)
    print("\nCheck the keys and output folders for the generated files.")


if __name__ == "__main__":
    main()