import socket
import pickle
from crypto.AsymmetricCipher import RSA
from crypto.SymmetricCipher import AESEncryption, Encryptor
from KeyManagement import KeyManager



class Client:
    def __init__(self) -> None:
        # Create a socket object
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Get local machine name
        self.host = socket.gethostname()
        self.port = 12345
   
        # generate iv and random key
        aes_strategy = AESEncryption()
        self.iv = aes_strategy.generate_iv()
        self.key256 = aes_strategy.generate_key(32)
        self.encryptor = Encryptor(aes_strategy)


    def client_up(self):
        # Connect to the server
        self.client_socket.connect((self.host, self.port))
        
        # 1. Receive the public key from the server
        response = self.client_socket.recv(4096)
        if not response:
            print("Error! Server did not send its public key.")
        else:
            print("Recieved public key from the server.")           
            # 2. Generate a random session key and iv, and send it along with the encryption scheme to the server
            # get public key object
            rsa = RSA()
            rsa_public_key = KeyManager().pem_to_rsa_public_key(pickle.loads(response)["public_key"])
            
            # encrypt the random key and iv with the servers public key
            data_to_send = {"mode": rsa.encrypt("AES256".encode(),rsa_public_key),
                            "key":rsa.encrypt(self.key256, rsa_public_key),
                            "iv":rsa.encrypt(self.iv, rsa_public_key)}
            
            # send the encrypted message
            self.client_socket.send(pickle.dumps(data_to_send))
            print("Key : ",self.key256,"\niv : ", self.iv)
            print("Sent session key and iv to server.")
        
        # prompt the user to login then encrypt all communication using key256
        user_request = input("Sign in --> 0\nSign up --> 1\n")
        while user_request:
            username = input("Username: ")
            password = input("Password: ")
            if user_request == "0":
                mode = "SignIn" 
            elif user_request == "1":
               mode = "SignUp"
            else:
                break
            data_to_send = {"mode":self.encryptor.encrypt_text(mode.encode(),self.key256,self.iv),
                            "username": self.encryptor.encrypt_text(username.encode(),self.key256,self.iv),
                            "password" : self.encryptor.encrypt_text(password.encode(),self.key256,self.iv)}
            self.client_socket.send(pickle.dumps(data_to_send))
            result = pickle.loads(self.client_socket.recv(4096))
            print(self.encryptor.decrypt_text(result, self.key256, self.iv).decode())
            user_request = input("Sign in --> 0\nSign up --> 1\nExit --> Enter\n")
        
        # Close the connection
        self.client_socket.close()    
        
        
if __name__=="__main__":
    client = Client()
    client.client_up()
