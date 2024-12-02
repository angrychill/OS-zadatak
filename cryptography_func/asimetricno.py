# Elliptic curve
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# jer nije preporuceno koristenje istih kljuceva za signing i exchange
# po dokumentaciji od cryptography library-a

# koristeci RSA
def generate_exchange_keys(private_key_path : Path, public_key_path : Path):
    # prateci documentation recommendatione:
    private_key : rsa.RSAPrivateKey = rsa.generate_private_key(65537, key_size=2048)
    public_key : rsa.RSAPublicKey = private_key.public_key()
    
    write_exchange_keys_to_file(private_key, public_key, private_key_path, public_key_path)

def write_exchange_keys_to_file(private_key : rsa.RSAPrivateKey, public_key : rsa.RSAPublicKey, private_key_path : Path, public_key_path : Path):
    filepath_private : Path = private_key_path
    filepath_public : Path = public_key_path

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    filepath_private.write_bytes(private_key_bytes)
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    filepath_public.write_bytes(public_key_bytes)

    
def encrypt_asymmetric(filepath_to_encrypt : Path, filepath_to_save : Path, filepath_public : Path):
    public_key = serialization.load_pem_public_key(filepath_public.read_bytes())
    message_to_encrypt = filepath_to_encrypt.read_bytes()
    encrypted = public_key.encrypt(message_to_encrypt,
                                   padding.OAEP(
                                       mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None
                                   ))
    filepath_to_save.write_bytes(encrypted)
    print("should have encrypted!")
    pass

def decrypt_asymmetric(filepath_to_decrypt : Path, filepath_to_save : Path, filepath_private : Path):
    private_key : rsa.RSAPrivateKey = serialization.load_pem_private_key(filepath_private.read_bytes(), password=None)
    message_to_decrypt = filepath_to_decrypt.read_bytes()
    decrypted = private_key.decrypt(
        message_to_decrypt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    filepath_to_save.write_bytes(decrypted)
    print("should have decrypted!")
