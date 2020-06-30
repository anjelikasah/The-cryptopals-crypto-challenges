import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def make_chunks(ciphertext, block_size):
    chunks = [ciphertext[i:i+block_size] for i in range (0,len(ciphertext), block_size)]
    return chunks

def get_xor_bytes(ciphertext,key):
    return bytes([ciphertext_char ^ key_char for ciphertext_char, key_char in zip(ciphertext, key)])

def AES_128_ECB_decrypt(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)

def AES_128_ECB_encrypt(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.encrypt(ciphertext)

def AES_CBC_decrypt(ciphertext,key,IV):
    keysize = len(key)
    chunks = make_chunks(ciphertext, keysize)
    last_block  = IV
    plaintext = b''

    for chunk in chunks:
        AES_decrypted = AES_128_ECB_decrypt(chunk, key)
        plaintext += get_xor_bytes(AES_decrypted,last_block)
        last_block = chunk
    return(unpad(plaintext,16))

def AES_CBC_encrypt(normal_byte_text,key, IV):
    keysize = len(key)
    normal_byte_text = pad(normal_byte_text,16)
    chunks = make_chunks(normal_byte_text, keysize)
    last_block  = IV
    plaintext = b''

    for chunk in chunks:
        xored = get_xor_bytes(chunk,last_block)
        AES_encrypted = AES_128_ECB_encrypt(xored, key)
        last_block = AES_encrypted
        plaintext += AES_encrypted
    return plaintext

if __name__ == "__main__":
    text = open("4_resource.txt", 'r').read()
    ciphertext = codecs.decode(bytes(text, encoding='utf-8'), 'base64')
    key = b'YELLOW SUBMARINE'
    IV = chr(0).encode() * len(key)
    print(AES_CBC_decrypt(ciphertext,key,IV).decode())
    
    test_text = b'Lorem Ipsum has been the industrys standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled'
    assert (AES_CBC_decrypt(AES_CBC_encrypt(test_text, key, IV), key, IV)) == test_text