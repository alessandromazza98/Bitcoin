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
def parse256(p):
    return int.from_bytes(p, 'big')


# Create a fingerprint of the serialized pub_key in input (starts w/ 02 or 03)
def fingerprint(pub_key_serialized):
    return ToolsUnit.hash160(pub_key_serialized)[:4]


# Serialization of extended keys (priv/pub keys + chain code)
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data
def ser_extended_keys(k: int, chain_code: bytes, index: int, level=0, parent_pub_key=b'\x00', master_key='False',
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
def deserialize_extended_key(extended_key: bytes):
    decode_key = base58.b58decode_check(extended_key)

    version_byte = decode_key[0:3]
    depth = decode_key[3:4]
    finger_print = decode_key[4:8]
    child_number = decode_key[8:12]
    chain_code = decode_key[13:45]
    private_key = decode_key[45:]

    return version_byte, depth, finger_print, child_number, chain_code, private_key


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
def CKDpriv(k_par, c_par, index):
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

    return k_i, c_i


# The function CKDpub(K_par_x, K_par_y, c_par, index) → (K_i, c_i) computes a
# child extended public key from the parent extended public key.
# It is only defined for non-hardened child keys.
# K = pub key in the point coordinate form (not serialized).
def CKDpub(K_par_x, K_par_y, c_par, index):
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

    return K_i_x, K_i_y, c_i


# Execute some tests
seed_hex = "000102030405060708090a0b0c0d0e0f"  # example test

xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
xpriv_decoded_frombase58 = base58.b58decode_check(xpriv)
chain_priv = xpriv_decoded_frombase58[13:]  # to extract only chain_code + priv_key
chain_code0 = chain_priv[:32]
priv0 = chain_priv[32:]

k0, c0 = master_key_generation(bytes.fromhex(seed_hex))
K0_x, K0_y = ECDSAUnit.multiply(k0)
K0ser = serP(K0_x, K0_y)

ser = ser_extended_keys(k0, c0, 0, master_key='True')

print(ser.decode())

ind = 2**31
k0h, c0h = CKDpriv(k0, c0, ind)
lev = 1
ser0h = ser_extended_keys(k0h, c0h, ind, lev, parent_pub_key=K0ser)
print(ser0h.decode())
