# AES
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes




def generate_secret_key(filepath : Path):
    # random koristeci OS clock
    # AES256
    
    # initialization vektor od 16 byta
    initialization_vector : bytes = os.urandom(16)
    # tajni kljuc od 32 byta ili 256 bita
    secret_key : bytes = os.urandom(32)

    write_secret_to_file(secret_key, initialization_vector, filepath)


def encrypt_symmetric(filepath_to_encrypt : Path, filepath_to_save : Path, secret_key_filepath : Path):
    full_data = secret_key_filepath.read_bytes()
    init_vec = full_data[:16]
    secret_key = full_data[16:]
    print(init_vec)
    print(secret_key)

    # output feedback
    # koristi stream mode da se ne brine o velicini blocka
    cipher = Cipher(algorithms.AES256(secret_key), modes.OFB(init_vec))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(filepath_to_encrypt.read_bytes()) + encryptor.finalize()
    filepath_to_save.write_bytes(encrypted)
    
    print("should have saved to file")
    
    pass

def decrypt_symmetric(filepath_to_decrypt : Path, filepath_to_save : Path, secret_key_filepath : Path):
    print("dekriptiraj asimetricno")
    full_data = secret_key_filepath.read_bytes()
    
    # prvih 16 byteova je initialization vektor, a ostatak je kljuc
    init_vec = full_data[:16]
    secret_key = full_data[16:]
    print(init_vec)
    print(secret_key)
    
    cipher = Cipher(algorithms.AES256(secret_key), modes.OFB(init_vec))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(filepath_to_decrypt.read_bytes()) + decryptor.finalize()
    
    filepath_to_save.write_bytes(decrypted)
    
    print("should have saved to file")

def write_secret_to_file(secret_key : bytes, initialization_vector : bytes, filepath : Path):
    filepath_secret_bytes : Path = filepath

    # direktno u bytes, pa nije human readable
    full_message : bytes = initialization_vector + secret_key
    filepath_secret_bytes.write_bytes(full_message)
    print("wrote secret bytes to file!")
