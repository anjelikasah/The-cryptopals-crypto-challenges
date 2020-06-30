import codecs
from string import printable

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

if __name__ == "__main__":
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    ciphertext = codecs.decode(hex_string,'hex')
    max_score = 0
    
    for char in printable:
        t = get_xor(ciphertext, char)
        score = get_score (t)
        if score>max_score:
            max_score = score
            possible_message = t
						key = char
		print ("message: ", possible_message.decode(), "\tkey: ",key, "\tscore: ", max_score)