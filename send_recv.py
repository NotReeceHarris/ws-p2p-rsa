from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import math
import string
import random

def generate_rsa_keys():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    # Get the public key from the private key
    public_key = private_key.public_key()
    
    # Serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_with_rsa(public_key_pem, plaintext):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    
    # Encrypt the data
    cipher_text = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return cipher_text

def decrypt_with_rsa(private_key_pem, cipher_text):
    # Load the private key
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    
    # Decrypt the data
    decrypted = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

def verify_public_rsa_key(public_key_pem):
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        if isinstance(key, rsa.RSAPublicKey):
            return True
        return False
    except ValueError:
        return False

def generate_random_string(length):
    """
    Generate a string of random characters with the given length, excluding hyphens.
    
    :param length: Integer, number of characters in the string
    :return: String of random characters without hyphens
    """
    # Define the possible characters, excluding hyphen
    characters = string.ascii_letters + string.digits + ''.join(c for c in string.punctuation if c != '-')
    # Generate the random string
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# ---------------------------- SEND / RECV ----------------------------

targets_public_key = None
our_private_key = None
our_public_key = None
payload_size = 446 # 512 bytes (key size) - 66 bytes (padding) = 446 

def disconnected():
    global targets_public_key, our_private_key, our_public_key
    targets_public_key = None
    our_private_key = None
    our_public_key = None

def connected(client):
    global our_private_key, our_public_key
    our_private_key, our_public_key = generate_rsa_keys()
    
    client.send(our_public_key)

def send(data):
    print(f"Sending: {data}")

    global our_private_key
    if our_private_key is None:
        print("Error: No private key")
        return None

    if len(data) > (payload_size - 2):
        print("Error: Data too large")
        return None

    random_data_size = math.floor(((payload_size - len(data)) - 2) / 2)
    payload = f'{generate_random_string(random_data_size)}-{data}-{generate_random_string(random_data_size)}'
    cipher_text = encrypt_with_rsa(targets_public_key, payload)

    return cipher_text

def recv(data):

    global targets_public_key

    if targets_public_key is None:
        if verify_public_rsa_key(data):
            targets_public_key = data
            return "Handshake complete"
        else:
            print(f"Invalid public key: {data}")
    else:
        decrypted = decrypt_with_rsa(our_private_key, data)
        payload = decrypted.split('-')
        data = payload[1]
        return data
