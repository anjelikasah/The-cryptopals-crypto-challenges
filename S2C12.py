import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from random import randint
from string import printable

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

def detection_oracle(ciphertext):
    block_size = 16
    chunks = make_chunks(ciphertext, block_size)
    if len(chunks) - len(set(chunks)) == 0:
        return "cbc"
    else:
        return "ecb"

def encryption_oracle(binary_buffer,key,unknown_string):
    appended_buffer = binary_buffer + unknown_string
    plaintext = pad(appended_buffer, 16)
    return AES_128_ECB_encrypt(plaintext,key)

def detect_size(len_ciphertext,binary_buffer,key_random,unknown_string):
    gradual_byte = b''
    new_len = len_ciphertext
    while len_ciphertext == new_len:
        gradual_byte += b'A'
        new_ciphertext = encryption_oracle(binary_buffer+gradual_byte,key_random,unknown_string)
        new_len = len(new_ciphertext)
    return new_len - len_ciphertext

def make_input_block(size):
    input_block = b'A'
    return input_block*(size-1)

def make_dictionary(input_block):
    dictionary = {}
    for char in printable:
        dictionary [char] = input_block + bytes(char, encoding='utf-8')
    return(dictionary)

def byte_at_a_time_ECB_decryption(unknown_string):
    key_random = randon_key_generator(16)
    binary_buffer = bytes([0]*64)
    ciphertext = encryption_oracle(binary_buffer,key_random, unknown_string)
    size = detect_size(len(ciphertext), binary_buffer, key_random, unknown_string)
    print("size of block \t", size)
    print("mode of encryption \t", detection_oracle(ciphertext))
    result = b''
    string_chunk = make_chunks(unknown_string,size)
    for unknown_string_block in string_chunk:
        byte_to_be_added = b""
        for i in range(size):
            input_block = make_input_block(size - i)
            dictionary = make_dictionary(input_block + byte_to_be_added)
            block = input_block + unknown_string_block
            chunks = make_chunks(block,16)
            input_block_ciphertext = encryption_oracle(chunks[0],key_random,b'')

            for i in dictionary:
                dictionary_ciphertext = encryption_oracle(dictionary[i],key_random, b'')
                if input_block_ciphertext == dictionary_ciphertext:
                    byte_to_be_added += bytes(i, 'utf-8')
                    result += bytes(i,'utf-8')
    return result.decode()

if __name__ == "__main__":
    unknown_string = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK"
    unknown_string_base64 = codecs.decode(unknown_string,'base64')
    print(byte_at_a_time_ECB_decryption(unknown_string_base64))
    
