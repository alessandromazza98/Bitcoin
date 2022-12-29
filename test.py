import hashlib
import hmac
import base58


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


seed_hex = "000102030405060708090a0b0c0d0e0f"  # example test
salt = "Bitcoin seed"  # from BIP-32

a = hmac.new(salt.encode(), bytes.fromhex(seed_hex), hashlib.sha512).digest()

aL = a[0:32]
aR = a[32:]

master_secret_key = parse256(aL)
master_chain_code = aR

xpriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi "
xpriv_decoded_frombase58 = base58.b58decode_check(xpriv)

chain_priv = xpriv_decoded_frombase58[13:]  # to extract only chain_code + priv_key

chain_code = chain_priv[:32]
priv = chain_priv[32:]

print(chain_code)
print(master_chain_code)

print()

print(int.from_bytes(priv, 'big'))
print(master_secret_key)
