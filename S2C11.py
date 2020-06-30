import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from random import randint

def make_chunks(ciphertext, block_size):
    chunks = [ciphertext[i:i+block_size] for i in range (0,len(ciphertext), block_size)]
    return chunks

def get_xor_bytes(ciphertext,key):
    return bytes([ciphertext_char ^ key_char for ciphertext_char, key_char in zip(ciphertext, key)])

def AES_128_ECB_decrypt(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)

def AES_128_ECB_encrypt(normal_byte_text, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.encrypt(normal_byte_text)

def AES_CBC_decrypt(ciphertext,key,IV):
    keysize = len(key)
    chunks = make_chunks(ciphertext, keysize)
    last_block  = IV
    plaintext = b''

    for chunk in chunks:
        AES_decrypted = AES_128_ECB_decrypt(chunk, key)
        plaintext += get_xor_bytes(AES_decrypted,last_block)
        last_block = chunk
    return(unpad(plaintext,keysize))

def AES_CBC_encrypt(normal_byte_text,key, IV):
    keysize = len(key)
    normal_byte_text = pad(normal_byte_text,keysize)
    chunks = make_chunks(normal_byte_text, keysize)
    last_block  = IV
    plaintext = b''

    for chunk in chunks:
        xored = get_xor_bytes(chunk,last_block)
        AES_encrypted = AES_128_ECB_encrypt(xored, key)
        last_block = AES_encrypted
        plaintext += AES_encrypted
    return plaintext

def randon_key_generator(key_size):
    return Random.new().read(key_size)

def encryption_oracle(binary_buffer,key_size):
    key = randon_key_generator(key_size)
    len_append = randint(5,10)
    appended_buffer = randon_key_generator(len_append) + binary_buffer + randon_key_generator(len_append)
    plaintext = pad(appended_buffer, 16)
    if randint(0,1):
        return AES_128_ECB_encrypt(plaintext,key),"ecb"
    else:
        IV = randon_key_generator(16)
        return AES_CBC_encrypt(plaintext,key, IV),"cbc"

def detection_oracle(ciphertext):
    block_size = 16
    chunks = make_chunks(ciphertext, block_size)
    if len(chunks) - len(set(chunks)) == 0:
        return "cbc"
    else:
        return "ecb"

if __name__ == "__main__":
    key_size = 16
    buffer = b"hello how are you? how are you? are you fine? are you fine? are you fine? are you fine? are you fine?"
    binary_buffer = codecs.encode(buffer,'hex')
    encryption, mode = encryption_oracle(binary_buffer,key_size)
    print("detected mode of encryption: \t",detection_oracle(encryption))
    
    input_data = bytes([0]*64)
    for i in range (1000):
        ciphertext, is_ecb_or_cbc = encryption_oracle(input_data, key_size)
        detect_ecb = detection_oracle(ciphertext)
        if is_ecb_or_cbc != detect_ecb:
            print("failed")