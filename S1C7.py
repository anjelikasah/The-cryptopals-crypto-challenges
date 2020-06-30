from Crypto.Cipher import AES
from base64 import b64decode

def AES_128_ECB(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)

if __name__ == "__main__":
    text = open("7_resource.txt", 'r').read()
    ciphertext = b64decode(text)
    key = b'YELLOW SUBMARINE'
    message = AES_128_ECB(ciphertext, key)
    print(message.decode())