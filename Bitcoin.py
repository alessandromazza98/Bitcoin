from hashlib import sha256
import ECDSA

# -------------------
# Create A Public Key
# -------------------
# Example private key (in hexadecimal)
private_key = "f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6"

public_key_x, public_key_y = ECDSA.multiply(int(private_key, 16))

public_key_x = hex(public_key_x)[2:].rjust(64, "0")  # extended in 64 characters = 32 bytes. If necessary pad w/ 0
public_key_y = hex(public_key_y)[2:].rjust(64, "0")

# uncompressed public key
uncompressed_public_key = "04" + public_key_x + public_key_y

# compressed public key
if int(public_key_y, 16) % 2 == 0:
    compressed_public_key = "02" + public_key_x
else:
    compressed_public_key = "03" + public_key_x

# print(compressed_public_key)


def tx(scriptsig):
    size_scriptsig = hex(len(scriptsig) // 2)[2:]
    return "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b00000000" + size_scriptsig \
        + scriptsig + "ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"


scriptpubkey = "76a9144299ff317fcd12ef19047df66d72454691797bfc88ac"  # un esempio ovviamente

transaction_unsigned = tx(scriptpubkey)


def add_sigHashAll(transaction):
    return transaction + "01000000"


transaction_unsigned = add_sigHashAll(transaction_unsigned)
# print(transaction_unsigned)


def hash256(hex_data):
    first_hash = sha256(bytes.fromhex(hex_data)).digest()
    return sha256(first_hash).hexdigest()


def sign_tx(private_key_int, tx_hash, k=None):
    return ECDSA.sign(private_key_int, tx_hash, k)


def encode_sign_DER(r, s):

    # convert r and s in hexadecimal using always 64 characters (32 bytes). Pad w/ 0 if necessary
    r_hex = hex(r)[2:].rjust(64, "0")
    s_hex = hex(s)[2:].rjust(64, "0")

    # add a "00" in front if the first byte of r or s is >= 0x80
    if int(r_hex[0:2], 16) >= int("80", 16):
        r_hex = "00" + r_hex

    if int(s_hex[0:2], 16) >= int("80", 16):
        s_hex = "00" + s_hex

    # calculate length of r_hex and s_hex in bytes
    r_hex_length = hex(len(r_hex) // 2)[2:].rjust(2, "0")
    s_hex_length = hex(len(s_hex) // 2)[2:].rjust(2, "0")

    # int type = "02" in DER encoding
    int_type = "02"

    # compound object = "30" in DER encoding
    compound_object = "30"

    # total length
    total_length = hex(2 * len(int_type) // 2 + 2 * len(r_hex_length) // 2
                       + int(r_hex_length, 16) + int(s_hex_length, 16))[2:].rjust(2, "0")

    return compound_object + total_length + int_type + r_hex_length + r_hex + int_type + s_hex_length + s_hex


def append_sighash(der_sig):
    return der_sig + "01"  # 01 = sighash ALL


# construct an unlocking script for P2PKH locking script
def script_sig(pk, der_sig):

    # calculate pk length
    pk_length = hex(len(pk) // 2)[2:].rjust(2, "0")

    # calculate der_sig length
    der_sig_length = hex(len(der_sig) // 2)[2:].rjust(2, "0")

    return der_sig_length + der_sig + pk_length + pk
