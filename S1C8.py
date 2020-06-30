from Crypto.Cipher import AES
from base64 import b64decode
import codecs
from string import printable
import collections

def find_repeated_chunk(chunks): 
    repeated_chunk =[]
    counts = 0
    for chunk, count in collections.Counter(chunks).items():
        if count>1:
            repeated_chunk.append(codecs.encode(chunk, 'hex').decode())
            counts = count
    return repeated_chunk, counts

def make_chunks(ciphertext_line, block_size):
    chunks = [ciphertext_line[i:i+block_size] for i in range (0,len(ciphertext_line), block_size)]
    repeated_chunk, no_of_occurrence = find_repeated_chunk(chunks)
    result = {
        'ciphertext' : ciphertext_line, 
        'repetition' : no_of_occurrence-1, 
        'chunks': repeated_chunk
    }
    return result
    
if __name__ == "__main__":
    text = open("8_resource.txt", 'r')
    block_size = 16
    repetition = []
    for line in text:
        ciphertext_line = codecs.decode(bytes(line.strip(), encoding='utf-8'), 'hex')
        repetition.append(make_chunks(ciphertext_line, block_size))
    most_repetation = sorted(repetition,key=lambda x: x['repetition'], reverse=True)[0]
    print(codecs.encode(most_repetation['ciphertext'], 'hex').decode())
    print(most_repetation['repetition'])
    print(most_repetation['chunks'])