import codecs

def hex_to_base64(hex_value):
    base64_value = codecs.encode(codecs.decode(hex_value, 'hex'), 'base64').decode().rstrip()
    return base64_value

if __name__ == "__main__":
    hex_value = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64_value = hex_to_base64(hex_value)
    print(base64_value)