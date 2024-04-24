from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os


# Define the interface for encryption algorithm
class EncryptionStrategy:
    def encrypt(self, text, key, iv):
        pass
    def decrypt(self, text, key, iv):
        pass
    
    
class DESEncryption(EncryptionStrategy):
    def generate_key(self):
        return os.urandom(8)
    
    def generate_iv(self):
        return get_random_bytes(8)
    
    def encrypt(self, text, key, iv):
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(text, DES.block_size))
        return ciphertext
    
    def decrypt(self, text, key, iv):
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = cipher.decrypt(text)
        return unpad(plaintext, DES.block_size)


# Implement encryption algorithms
class AESEncryption(EncryptionStrategy):  
    def generate_key(self, size):
        return os.urandom(size)
    
    def generate_iv(self):
        return os.urandom(16)
    
    def pad(self, plaintext):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext)
        padded_data += padder.finalize()
        return padded_data

    # Function to unpad the plaintext
    def unpad(self, padded_data):
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_data)
        unpadded_data += unpadder.finalize()
        return unpadded_data  
    
    def encrypt(self, text, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(self.pad(text)) + encryptor.finalize()
        return ciphertext
    
    def decrypt(self, text, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(text) + decryptor.finalize()
        return self.unpad(plaintext)


# Context class that uses the chosen encryption strategy
class Encryptor:
    def __init__(self, strategy:EncryptionStrategy):
        self.strategy = strategy

    def set_strategy(self, strategy:EncryptionStrategy):
        self.strategy = strategy

    def encrypt_text(self, text, key, iv):
        return self.strategy.encrypt(text, key, iv)
    
    def decrypt_text(self, text, key, iv):
        return self.strategy.decrypt(text, key, iv)


# Example usage
if __name__ == "__main__":   

    plainText = "Hello, world!".encode()
    print("\n\n",plainText,end="\n\n\n")
    
    aes_strategy = AESEncryption()
    iv = aes_strategy.generate_iv()

    # Example usage of AES128
    key128 = aes_strategy.generate_key(16)
    encryptor = Encryptor(aes_strategy)
    cipher_text_AES128 = encryptor.encrypt_text(plainText, key128, iv)
    deciphered_text_AES128 = encryptor.decrypt_text(cipher_text_AES128, key128, iv)
    print("\tAES128\nCipherText: ",cipher_text_AES128,"\nDecipheredText: ",deciphered_text_AES128, end="\n\n")
    
    # Example usage of AES192
    key192 = aes_strategy.generate_key(24)
    encryptor = Encryptor(aes_strategy)
    cipher_text_AES192 = encryptor.encrypt_text(plainText, key192, iv)
    deciphered_text_AES192 = encryptor.decrypt_text(cipher_text_AES192, key192, iv)
    print("\tAES192\nCipherText: ",cipher_text_AES192,"\nDecipheredText: ",deciphered_text_AES192, end="\n\n")
    
    # Example usage of AES256
    key256 = aes_strategy.generate_key(32)
    encryptor = Encryptor(aes_strategy)
    cipher_text_AES256 = encryptor.encrypt_text(plainText, key256, iv)
    deciphered_text_AES256 = encryptor.decrypt_text(cipher_text_AES256, key256, iv)
    print("\tAES256\nCipherText: ",cipher_text_AES256,"\nDecipheredText: ",deciphered_text_AES256, end="\n\n")

    # Example usage of DES
    des_strategy = DESEncryption()
    key64 = des_strategy.generate_key()
    iv_8 = des_strategy.generate_iv()
    encryptor = Encryptor(des_strategy)
    cipher_text_DES = encryptor.encrypt_text(plainText, key64, iv_8)
    deciphered_text_DES = encryptor.decrypt_text(cipher_text_DES, key64, iv_8)
    print("\tDES\nCipherText: ",cipher_text_DES,"\nDecipheredText: ",deciphered_text_DES, end="\n\n")