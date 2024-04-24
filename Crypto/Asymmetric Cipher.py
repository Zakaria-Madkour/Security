from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class RSA():
    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
            )
        public_key = private_key.public_key()
        return public_key, private_key
    
    def encrypt(self, text, public_key):
        ciphertext = public_key.encrypt(
                    text,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
        )
        return ciphertext
    
    def decrypt(self, text, private_key):
        decrypted_text = private_key.decrypt(
                text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
        )
        return decrypted_text
    
    def generate_digital_signature(self, message, private_key):
        signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
        )
        return signature
    
    def verify_digital_signature(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
        

if __name__ == '__main__':
    
    plainText = "Hello, world!".encode()
    
    rsa_object = RSA()
    public_key, private_key = rsa_object.generate_key_pair()

    # Encryption
    ciphertext = rsa_object.encrypt(plainText, public_key)
    deciphered_text = rsa_object.decrypt(ciphertext, private_key)
    print("\nText: ",plainText,"\n\nCiphertext: ",ciphertext,"\n\nDeciphered Text: ",deciphered_text, end="\n\n")
    
    # Digital Signature
    digital_signature = rsa_object.generate_digital_signature(plainText, private_key)
    print("Digitally signed message: ", digital_signature)
    validate = rsa_object.verify_digital_signature(plainText, digital_signature, public_key)
    print("\nDigital Signature Validation state: ",validate,end="\n\n")
    
    #Failed verification
    public_key2, private_key2 = rsa_object.generate_key_pair()
    validate2 = rsa_object.verify_digital_signature(plainText, digital_signature, public_key2)
    print("\nDigital Signature Validation state: ",validate2,end="\n\n")
    