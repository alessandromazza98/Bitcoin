import ECDSA


# Transform little endian <-> big endian notation
def reverse_byte_order(hex_data):
    return bytes.hex(bytes.fromhex(hex_data)[::-1])


# Calculate compressed pk from sk
def calculate_compressed_pk(sk_int):
    public_key_x, public_key_y = ECDSA.multiply(sk_int)

    public_key_x = hex(public_key_x)[2:].rjust(64, "0")  # extended in 64 characters = 32 bytes. If necessary pad w/ 0
    public_key_y = hex(public_key_y)[2:].rjust(64, "0")

    # compressed public key
    if int(public_key_y, 16) % 2 == 0:
        compressed_public_key = "02" + public_key_x
    else:
        compressed_public_key = "03" + public_key_x

    return compressed_public_key

