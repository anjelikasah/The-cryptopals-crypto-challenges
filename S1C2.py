import codecs

def xor(hex1,hex2):
    int1 = int(hex1,16)
    int2 = int(hex2,16)
    hex_final = hex(int1^int2)[2:]
    return hex_final

if __name__ == "__main__":
    hex1 = "1c0111001f010100061a024b53535009181c"
    hex2 = "686974207468652062756c6c277320657965"
    print (xor (hex1,hex2))