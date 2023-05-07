import hashlib
import bcrypt
import argon2
import binascii

def encrypt_string(string_to_encrypt):
    # Convert string to UTF-16 encoded bytes
    utf16_bytes = string_to_encrypt.encode('utf-16le')

    # Generate SHA-512 hash of the UTF-16 bytes
    sha512_hash = hashlib.sha512(utf16_bytes).hexdigest()

    # Generate bcrypt hash of the SHA-512 hash
    bcrypt_hash = bcrypt.hashpw(sha512_hash.encode(), bcrypt.gensalt())

    # Generate Argon2 hash of the SHA-512 hash
    #argon2_hash = argon2.PasswordHasher().hash(sha512_hash.encode())

    # Generate PBKDF2 hash of the SHA-512 hash
    pbkdf2_hash = hashlib.pbkdf2_hmac('sha512', sha512_hash.encode(), b'salt', 100000)

    # Convert the PBKDF2 hash to a hexadecimal string
    pbkdf2_hash_hex = binascii.hexlify(pbkdf2_hash).decode('ascii')

    # Return all the hashes as a tuple
    return (sha512_hash, bcrypt_hash, pbkdf2_hash_hex)

# Example usage
string_to_encrypt = "Hello, World!"
encrypted_values = encrypt_string(string_to_encrypt)
print(f"SHA-512 hash: {encrypted_values[0]}")
print(f"bcrypt hash: {encrypted_values[1]}")
#print(f"Argon2 hash: {encrypted_values[2]}")
print(f"PBKDF2 hash: {encrypted_values[2]}")
