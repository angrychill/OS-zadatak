import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# koristi SHA256 jer blake2 ne podrzava neke funkcionalnosti za enkripciju
def calculate_file_hash(file_to_hash : Path, file_to_save : Path):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_to_hash.read_bytes())
    data_to_save = digest.finalize()
    file_to_save.write_bytes(data_to_save)
    print(data_to_save)
    print("should've saved hash!")
    

# koristi hasher zbog ekstra sigurnosti kod duljine poruke
def generate_digital_signature(file_to_sign : Path, private_key_path : Path, file_to_save_signature : Path):
   chosen_hash = hashes.SHA256()
   hasher = hashes.Hash(chosen_hash)
   hasher.update(file_to_sign.read_bytes())
   digest = hasher.finalize()
   
   private_key : rsa.RSAPrivateKey = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
   
   signature = private_key.sign(
       digest,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       utils.Prehashed(chosen_hash)
   )
   
   file_to_save_signature.write_bytes(signature)
   print("saved digital signature!")
   
   

def check_digital_signature(file_to_check : Path, signature_path : Path, public_key_path : Path) -> bool:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(file_to_check.read_bytes())
    digest = hasher.finalize()
    signature = signature_path.read_bytes()
    
    public_key : rsa.RSAPublicKey = serialization.load_pem_public_key(public_key_path.read_bytes())
    
    
    try:
        public_key.verify(
        signature,
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash))
        return True
    except Exception as e:
        return False
        