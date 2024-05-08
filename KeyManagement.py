import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto.AsymmetricCipher import RSA

class KeyManager:
    def __init__(self, ):
        self.key_dir = "./keys"
        if not os.path.exists(self.key_dir):
            os.mkdir(self.key_dir)
    
    def get_key_pair(self, email):
        user_key_dir = self.key_dir+ "/"+ email
        # check if the email already has key pair then return them
        if os.path.exists(user_key_dir):
            with open((user_key_dir+"/"+'public.pem'), 'rb') as f:
                public_key = f.read()
            with open((user_key_dir+"/"+'private.pem'), 'rb') as f:
                private_key = f.read()   
        else:
            # 1. create a key pair
            rsa = RSA()
            public_key, private_key = rsa.generate_key_pair()
            # 2. create a directory by the email and store the key pair there
            os.mkdir(user_key_dir)
            # 3. store the key pair
            with open((user_key_dir+"/"+'private.pem'), 'wb') as f:
                private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                f.write(private_key)
            with open((user_key_dir+"/"+'public.pem'), 'wb') as f:
                public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                f.write(public_key)
        return public_key.decode(), private_key.decode()
    
    def pem_to_rsa_public_key(self, public_pem):
        # Load the PEM-encoded public key
        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
        return public_key
    
    def pem_to_rsa_private_key(self, private_pem):
       # Load the PEM-encoded private key
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,  # Provide the password if the key is encrypted
            backend=default_backend()
        )
        return private_key  
            
if __name__=="__main__":
    key_manager = KeyManager()
    public, private = key_manager.get_key_pair("admin")
    print("Public key: ",public,"\nPrivate Key: ",private)