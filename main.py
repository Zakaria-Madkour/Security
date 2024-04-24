import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class EncryptionWorker(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue):
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = get_random_bytes(16) # AES key must be either 16, 24, or 32 bytes long
        self.cipher = AES.new(self.key, AES.MODE_EAX)
    
    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                break
            ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)
            self.ciphertext_queue.put((ciphertext, tag))
            
# Usage:
# plaintext_queue = queue.Queue()
# ciphertext_queue = queue.Queue()
# worker = EncryptionWorker(plaintext_queue, ciphertext_queue)
# worker.start()
# ...
# worker.join()

    
    
    
#TODO: 
#      2. SHA Hashing function
#      3. RSA public key crypto system