import hashlib
import base58
import ECDSAUnit
from hashlib import sha256


# Transform little endian <-> big endian notation
# In input takes a string hex data
# It outputs a string hex data
def reverse_byte_order(hex_data):
    return bytes.hex(bytes.fromhex(hex_data)[::-1])


# Calculate pk from sk
def calculate_pk(sk):
    return ECDSAUnit.multiply(sk)


# Turn pk from int to string in uncompressed form
def turn_pk_from_int_to_uncompressed(pk_x, pk_y):
    pubk_x = hex(pk_x)[2:].rjust(64, "0")  # extended in 64 characters = 32 bytes. If necessary pad w/ 0
    pubk_y = hex(pk_y)[2:].rjust(64, "0")

    return "04" + pubk_x + pubk_y


# Turn pk from int to string in compressed form
def turn_pk_from_int_to_compressed(pk_x, pk_y):
    pubk_x = hex(pk_x)[2:].rjust(64, "0")  # extended in 64 characters = 32 bytes. If necessary pad w/ 0

    if pk_y % 2 == 0:
        compressed_pk = "02" + pubk_x
    else:
        compressed_pk = "03" + pubk_x

    return compressed_pk


# Compute hash256(hex_data) = sha256(sha256(hex_data))
# In input takes a string hex data
# It outputs a string hex data
def hash256(hex_data):
    return sha256(sha256(bytes.fromhex(hex_data)).digest()).hexdigest()


# Compute the hash160(hex_data) = ripemd160(sha256(hex_data))
# In input takes a string hex data
# It outputs a string hex data
def hash160(hex_data):
    first_hash = sha256(bytes.fromhex(hex_data)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(first_hash)
    return ripemd160.hexdigest()


# Compute varint(hex_data) = length(hex_data)
# In input takes a string hex data
# It outputs a string hex data
def calculate_varint(hex_data):
    return hex(len(hex_data) // 2)[2:].rjust(2, "0")  # at least 2 chars, pad w/ 0 if necessary


# Calculate the BTC address from a pk_hash160 and a version prefix (default="00" -> mainnet standard P2PKH)
# In input takes a string hex data (pk_hash160) and optional a string hex version_prefix
# It outputs a string hex data (btc address)
def pk_hash_to_btc_address(pk_hash160, version_prefix="00"):
    return base58.b58encode_check(bytes.fromhex(version_prefix + pk_hash160)).decode()


# Decode Base58Check from address to payload
# In input takes a string hex data (btc address)
# It outputs a string hex data (pk_hash160)
def btc_addr_to_pk_hash(btc_addr):
    # Base 58 decode the Bitcoin address.
    decoded_addr = base58.b58decode(btc_addr)
    # Covert the address from bytes to hex.
    decoded_addr_hex = bytes.hex(decoded_addr)
    # Obtain the RIPEMD-160 hash by removing the first and four last bytes of the decoded address, corresponding to
    # the version prefix and the checksum of the address.
    return decoded_addr_hex[2:-8]


# Create an output P2PKH from a given address (P2PKH = DUP HASH160 pk_hash_length pk_hash EQUALVERIFY CHECKSIG)
# In input takes a string hex data (btc address)
# It outputs a string hex data (P2PKH script)
def create_output_p2pkh(address):
    dup = "76"
    hash_160 = "a9"
    pk_hash = btc_addr_to_pk_hash(address)
    pk_hash_length = calculate_varint(pk_hash)
    equalverify = "88"
    checksig = "ac"
    return dup + hash_160 + pk_hash_length + pk_hash + equalverify + checksig


# Create an unlocking script
# In input takes two string hex data (der sig, pk_hex)
# It outputs a string hex data (unlocking_script)
def create_unlocking_script(der_sig, pk_hex):
    return calculate_varint(der_sig) + der_sig + calculate_varint(pk_hex) + pk_hex


# Derivation of address
