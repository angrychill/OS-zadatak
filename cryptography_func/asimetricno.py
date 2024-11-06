# Elliptic curve

from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# jer nije preporuceno koristenje istih kljuceva za signing i exchange
# po dokumentaciji od cryptography library-a

# koristeci RSA
def generate_exchange_keys()  -> tuple[Path, Path]:
    # prateci documentation recommendatione:
    private_key : rsa.RSAPrivateKey = rsa.generate_private_key(65537, key_size=2048)
    public_key : rsa.RSAPublicKey = private_key.public_key()
    
    return write_exchange_keys_to_file(private_key, public_key)

def write_exchange_keys_to_file(private_key : rsa.RSAPrivateKey, public_key : rsa.RSAPublicKey) -> tuple[Path, Path]:
    filepath_private : Path = Path("files/privatni_kljuc.txt")
    filepath_public : Path = Path("files/javni_kljuc.txt")

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    try:
        with open(filepath_private, 'wb') as file:
            file.write(private_key_bytes)
            print("wrote private to file!")
        # print(private_key_bytes)
        
    except Exception as e:
        print("failed to write private to file")
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    try:
        with open(filepath_public, 'wb') as file:
            file.write(public_key_bytes)
            print("wrote public to file!")
        # print(private_key_bytes)
        
    except Exception as e:
        print("failed to write public to file")
    
    return filepath_private, filepath_public
    
def encrypt_asymmetric(file : Path):
    content_to_encrypt = file.read_text()
    print("kriptiraj asimetricno")
    pass

def decrypt_asymmetric(file):
    print("dekriptiraj asimetricno")
    pass
