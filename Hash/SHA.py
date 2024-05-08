from cryptography.hazmat.primitives import hashes


def hash(text):
    # Choose a hash algorithm (SHA-256 in this example)
    algorithm = hashes.SHA256()
    hasher = hashes.Hash(algorithm)
    hasher.update(text.encode('utf-8'))
    # Finalize the hash to obtain the digest (hash value) of the data
    return hasher.finalize()

if __name__ == '__main__':
    plainText = "Hello, world!".encode()
    hashed_data = hash(plainText)
    print("Text: ",plainText,"\nHash: ",hashed_data)

