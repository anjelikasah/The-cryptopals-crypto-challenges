def pkcs_7_padding(block, block_size):
    padding_size = (block_size - len(block)) % block_size
    if padding_size == 0:
        padding_size = block_size
    return (chr(padding_size)*padding_size).encode()