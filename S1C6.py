import codecs
from string import printable
from itertools import combinations

def get_score(result_hex):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    score = 0
    for byte in result_hex.lower():
        score += character_frequencies.get(chr(byte),0)
    return score

def get_xor(ciphertext,key):
    result = b''
    for byte in ciphertext:
        result += bytes([byte ^ ord(key)])
    return result

def get_single_char_xor(ciphertext):
    max_score = 0
    for char in printable:
        t = get_xor(ciphertext, char)
        score = get_score (t)
        if score>max_score:
            max_score = score
            possible_message = t
            key = char
    return ord(key)

def repeating_key_xor(ciphertext, key):
    message = b''
    i = 0
    for byte in ciphertext:
        message += bytes([byte ^ key[i]])
        i = i + 1 if i < len(key) - 1 else 0 # Cycle i to point to the next byte of the key
    return message

def hamming_distance(binary_seq_1, binary_seq_2):
    dist = 0
    for byte1, byte2 in zip(binary_seq_1, binary_seq_2):
        diff = byte1 ^ byte2 # gets XOR of byte1 and byte2 
        dist += sum([1 for bit in bin(diff) if bit == '1']) # gets bit difference using XOR'd value
    return dist

def find_possible_key_sizes(ciphertext):
    normalized_distances = {}
    for key_size in range(2,41):
        # making chunks of ciphertext
        chunks = []
        for i in range(0, len(ciphertext), key_size):
            chunks.append(ciphertext[i:i + key_size])
        chunks = chunks[:4] # takes only 4 chunks
        distance = 0
        pairs = combinations(chunks, 2)
        for (x, y) in pairs:
            distance += hamming_distance(x, y)
        distance /= 2 # divide by 2 to get average distance because we have 2 pairs with 4 chunks. So 2 hamming distances.
        normalized_distance = distance / key_size
        normalized_distances[key_size] = normalized_distance
    possible_key_sizes = sorted (normalized_distances, key = normalized_distances.get)[:3] # takes 3 shortest normalized distances
    return possible_key_sizes

def find_possible_plaintext(ciphertext,possible_key_sizes):
    possible_plaintext = []
    for one_key_size in possible_key_sizes:
        key = b''
        # Breaks the ciphertext into blocks of one_key_size length
        for i in range(one_key_size):
            block = b''
            # Transpose the block that is the i-th byte of every block
            for j in range(i, len(ciphertext), one_key_size):
                block += bytes([ciphertext[j]])
            key += bytes([get_single_char_xor(block)]) # solves each block as a single character Xor
        possible_plaintext.append((repeating_key_xor(ciphertext,key),key))
    return (max(possible_plaintext, key=lambda k: get_score(k[0])))

if __name__ == "__main__":       
    text_file = open("6_resource.txt", "r")
    text = text_file.read()
    ciphertext = codecs.decode(bytes(text, encoding= 'utf-7'),'base64')

    possible_key_sizes = find_possible_key_sizes(ciphertext) # gets 3 most probable key sizes.
    possible_plaintext = find_possible_plaintext(ciphertext,possible_key_sizes) # gets possible message on the basis of ciphertext and key sizes.
    print(possible_plaintext[0].decode().rstrip())
    print("\n\nkey: ", possible_plaintext[1].decode())