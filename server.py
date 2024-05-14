import socket
import pickle
from crypto.AsymmetricCipher import RSA
from KeyManagement import KeyManager
from crypto.SymmetricCipher import Encryptor, AESEncryption, DESEncryption
from Authenticate import Authenticator

class Server:
    def __init__(self) -> None:
        # Create a socket object
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Get local machine name
        self.host = socket.gethostname()
        self.port = 12345   
        self.session_key = None
        self.session_iv = None 
        self.session_encryptor = None
        self.auth = Authenticator()
            
        
    def server_up(self):
        # Bind to the port
        self.server_socket.bind((self.host, self.port))
        # Listen for incoming connections
        self.server_socket.listen(10)

        while True:
            # Establish connection with client
            client_socket, addr = self.server_socket.accept()
            print('Got connection from client at: ', addr)
            
            # 1. generate public and private key pairs and send the public key to the client
            key_manager = KeyManager()
            public_key_pem, private_key_pem = key_manager.get_key_pair("server")
            rsa = RSA()
            private_key = key_manager.pem_to_rsa_private_key(private_key_pem)
            client_socket.send(pickle.dumps({"public_key":public_key_pem}))
            print("Sent public key to the client.") 
            
            # 2. recieve the session random key and session symmetric encryption algorithm
            data = client_socket.recv(4096)
            if not data:
                print("Error! Client didnt send session random key.")
            else:
                # Unpickle received data
                received_dict = pickle.loads(data)
                received_dict["mode"] = rsa.decrypt(received_dict["mode"], private_key).decode()
                self.session_key = received_dict["key"] = rsa.decrypt(received_dict["key"], private_key)
                self.session_iv = received_dict["iv"] = rsa.decrypt(received_dict["iv"], private_key)               
                print("Received dictionary:", received_dict)
                # set the session encryptor
                if received_dict["mode"][:3] == "AES":
                    self.session_encryptor = Encryptor(AESEncryption())
                elif received_dict["mode"][:3] == "DES":
                    self.session_encryptor = Encryptor(DESEncryption())
                print("Finished Handshake. Waiting for client request.")    
            
            
            data =client_socket.recv(4096)
            while(data):
                data =  pickle.loads(data)
                # decrypt
                data_recieved = {"mode":self.session_encryptor.decrypt_text(data["mode"],self.session_key,self.session_iv).decode(),
                            "username": self.session_encryptor.decrypt_text(data["username"],self.session_key,self.session_iv).decode(),
                            "password" : self.session_encryptor.decrypt_text(data["password"],self.session_key,self.session_iv).decode()}
                print(data_recieved)
                # serve
                if data_recieved["mode"] == "SignIn":
                    result = self.auth.authenticate_user(data_recieved["username"],data_recieved["password"])
                    result = "Login status" + str(result)
                elif data_recieved["mode"] == "SignUp":
                    result = self.auth.add_new_user(data_recieved["username"], data_recieved["password"])
                # respond
                print(result)
                client_socket.send(pickle.dumps(self.session_encryptor.encrypt_text(result.encode(), self.session_key, self.session_iv)))
                data =client_socket.recv(4096)
        # Close the server socket
        self.server_socket.close()



if __name__ == "__main__":
    server = Server()
    server.server_up()