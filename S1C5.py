import codecs
from math import floor

def get_xor(Sentence, key):
    byte = b''
    for char,key_no in zip(Sentence,key):
        xord= ord(char)^ord(key_no)
        byte += bytes([xord])
    return (codecs.encode(byte,'hex').decode())

def repeat_key(key,Sentence):
    length = floor(len(Sentence)/3) 
    for i in range (length):
        key += "ICE"
    return key

if __name__ == "__main__":    
    Sentence = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key = repeat_key("ICE", Sentence)
    print(get_xor(Sentence,key))