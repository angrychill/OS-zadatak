# AES
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_secret_key(*args) -> Path:
    # random koristeci OS clock
    # AES256
    
    secret_key : bytes = os.urandom(32)
    initialization_vector : bytes = os.urandom(16)
    
    return write_secret_to_file(secret_key)


def encrypt_symmetric(*args):
    print("kriptiraj simetricno")
    pass

def decrypt_symmetric(*args):
    print("dekriptiraj asimetricno")
    pass

def write_secret_to_file(secret_key : bytes) -> Path:
    filepath_secret_bytes : Path = Path("files/tajni_kljuc_bytes.txt")
    filepath_secret_txt : Path = Path("files/tajni_kljuc.txt")

    # direktno u bytes, pa nije human readable
    filepath_secret_bytes.write_bytes(secret_key)
    print("wrote secret bytes to file!")
    
    filepath_secret_txt.write_text(secret_key.hex())

    return filepath_secret_txt