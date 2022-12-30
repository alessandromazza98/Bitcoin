import hashlib
import hmac
import base58
import ECDSAUnit
import ToolsUnit

# number of points on the curve we can hit ("order")
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
# from BIP-32
salt = "Bitcoin seed"


# Serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
def ser32(i: int):
    return i.to_bytes(4, 'big')


# Serializes the integer i as a 32-byte sequence, most significant byte first.
def ser256(i: int):
    return i.to_bytes(32, 'big')


# Serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form:
# (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
def serP(px, py):
    if py % 2 == 0:
        return b'\x02' + ser256(px)
    else:
        return b'\x03' + ser256(px)


# Interprets a 32-byte sequence as a 256-bit number, most significant byte first.
def parse256(p: bytes):
    return int.from_bytes(p, 'big')


# Interprets a byte sequence as a int number, most significant byte first
def parse(byte: bytes):
    return parse256(byte)


# Create a fingerprint of the serialized pub_key in input (starts w/ 02 or 03)
def fingerprint(pub_key_serialized):
    return ToolsUnit.hash160(pub_key_serialized)[:4]


# Serialization of extended priv keys (priv key + chain code)
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data
def ser_extended_priv_keys(k: int, chain_code: bytes, index: int, level=0, parent_pub_key=b'\x00', master_key='False',
                           mainnet='True'):
    if mainnet == 'True':
        version_byte = b'\x04\x88\xAD\xE4'
    else:
        version_byte = b'\x04\x35\x83\x94'
    depth = level.to_bytes(1, 'big')
    if master_key == 'True':
        finger_print = b'\x00\x00\x00\x00'
    else:
        finger_print = fingerprint(parent_pub_key)
    child_number = ser32(index)

    key = version_byte + depth + finger_print + child_number + chain_code + b'\x00' + ser256(k)

    return base58.b58encode_check(key)


# De-serialize extended private key
def parse_extended_priv_key(extended_key: bytes):
    decode_key = base58.b58decode_check(extended_key)

    version_byte = decode_key[0:4].hex()
    depth = parse(decode_key[4:5])
    finger_print = decode_key[5:9].hex()
    child_number = parse(decode_key[9:13])
    chain_code = decode_key[13:45]
    private_key = parse256(decode_key[47:])  # byte 45-45 are b'\x00\x00' -> discarded

    return version_byte, depth, finger_print, child_number, chain_code, private_key


# Serialization of extended pub keys (pub key + chain code)
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data
def ser_extended_pub_keys(K_x: int, K_y: int, chain_code: bytes, index: int, level=0, parent_pub_key=b'\x00',
                          master_key='False', mainnet='True'):
    if mainnet == 'True':
        version_byte = b'\x04\x88\xB2\x1E'
    else:
        version_byte = b'\x04\x35\x87\xCF'
    depth = level.to_bytes(1, 'big')
    if master_key == 'True':
        finger_print = b'\x00\x00\x00\x00'
    else:
        finger_print = fingerprint(parent_pub_key)
    child_number = ser32(index)

    key = version_byte + depth + finger_print + child_number + chain_code + serP(K_x, K_y)

    return base58.b58encode_check(key)


# De-serialize extended public key
def parse_extended_pubkey(extended_key: bytes):
    decode_key = base58.b58decode_check(extended_key)

    version_byte = decode_key[0:4].hex()
    depth = parse(decode_key[4:5])
    finger_print = decode_key[5:9].hex()
    child_number = parse(decode_key[9:13])
    chain_code = decode_key[13:45]
    ser_public_key = bytes.hex(decode_key[45:])  # starts w/ 02 or 03

    return version_byte, depth, finger_print, child_number, chain_code, ser_public_key


# Generation of extended keys from seed (in bytes)
def master_key_generation(seed_bytes: bytes):
    a = hmac.new(salt.encode(), seed_bytes, hashlib.sha512).digest()
    aL = a[0:32]
    aR = a[32:]
    master_secret_key = parse256(aL)
    master_chain_code = aR

    return master_secret_key, master_chain_code


# The function CKDpriv(k_par, c_par, index) → (k_i, c_i) computes a child
# extended private key from the parent extended private key
def CKDpriv(xpriv, index):
    k_par, c_par = xpriv
    # check if it's hardened derivation (index >= 2**31)
    if index >= 2 ** 31:
        h = hmac.new(c_par, b'\x00' + ser256(k_par) + ser32(index), hashlib.sha512).digest()
    else:
        px, py = ECDSAUnit.multiply(k_par)
        h = hmac.new(c_par, serP(px, py) + ser32(index), hashlib.sha512).digest()

    hL = h[0:32]
    hR = h[32:]

    k_i = (parse256(hL) + k_par) % n
    c_i = hR

    if parse256(hL) >= n or k_i == 0:
        return IOError("ERRORE, NON è VALIDO!")

    xpriv_child = k_i, c_i
    return xpriv_child


# The function CKDpub(K_par_x, K_par_y, c_par, index) → (K_i, c_i) computes a
# child extended public key from the parent extended public key.
# It is only defined for non-hardened child keys.
# K = pub key in the point coordinate form (not serialized).
def CKDpub(xpub, index):
    K_par_x, K_par_y, c_par = xpub
    # Check if i ≥ 2**31, return error if it's true
    if index >= 2 ** 31:
        return IOError("CKDpub è definita solo per non-hardened keys")

    h = hmac.new(c_par, serP(K_par_x, K_par_y) + ser32(index))

    hL = h[0:32]
    hR = h[32:]

    hL_x, hL_y = ECDSAUnit.multiply(parse256(hL))

    K_i_x = hL_x + K_par_x
    K_i_y = hL_y + K_par_y

    c_i = hR

    if parse256(hL) >= n:
        return IOError("ERRORE, NON è VALIDO!")

    xpub_child = K_i_x, K_i_y, c_i
    return xpub_child


# Execute some tests
seed_hex = "000102030405060708090a0b0c0d0e0f"  # example test

k_master, c_master = master_key_generation(bytes.fromhex(seed_hex))
K_master_x, K_master_y = ECDSAUnit.multiply(k_master)
K_master_ser = serP(K_master_x, K_master_y)

ser = ser_extended_priv_keys(k_master, c_master, 0, master_key='True')
serpub = ser_extended_pub_keys(K_master_x, K_master_y, c_master, 0, 0, master_key='True')


xpriv_m_0h_1_2h = CKDpriv(CKDpriv(CKDpriv((k_master, c_master), 2**31), 1), 2**31 + 2)
k_m_0h_1_2h, c_m_0h_1_2h = xpriv_m_0h_1_2h
K_m_0h_1_2h_x, K_m_0h_1_2h_y = ECDSAUnit.multiply(k_m_0h_1_2h)
K_ser_m_0h_1_2h = serP(K_m_0h_1_2h_x, K_m_0h_1_2h_y)

k_m_0h_1_2h_2, c_m_0h_1_2h_2 = CKDpriv(xpriv_m_0h_1_2h, 2)

xpriv_ser_m_0h_1_2h = ser_extended_priv_keys(k_m_0h_1_2h_2, c_m_0h_1_2h_2, 2, 4, K_ser_m_0h_1_2h)
print(xpriv_ser_m_0h_1_2h)
