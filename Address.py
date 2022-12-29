import hashlib
import base58
from hashlib import sha256

import Bitcoin
import Tools


# Create an output from a given address (P2PKH = DUP HASH160 pk_hash_length pk_hash EQUALVERIFY CHECKSIG)
def create_1output_p2pkh(address):
    dup = "76"
    hash160 = "a9"
    pk_hash = btc_addr_to_hash_160(address)
    pk_hash_length = hex(len(pk_hash) // 2)[2:]
    equalverify = "88"
    checksig = "ac"
    return dup + hash160 + pk_hash_length + pk_hash + equalverify + checksig


# Compute the hash160 of the input data
def hash160(hex_data):
    first_hash = sha256(bytes.fromhex(hex_data)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(first_hash)
    return ripemd160.hexdigest()


# Calculate the BTC address from a pk and a version prefix
def pk_to_btc_address(pk, version_prefix="00"):
    pk_hash160 = hash160(pk)

    return base58.b58encode_check(bytes.fromhex(version_prefix + pk_hash160)).decode()


# Decode Base58Check from address to payload
def btc_addr_to_hash_160(btc_addr):
    # Base 58 decode the Bitcoin address.
    decoded_addr = base58.b58decode(btc_addr)
    # Covert the address from bytes to hex.
    decoded_addr_hex = bytes.hex(decoded_addr)
    # Obtain the RIPEMD-160 hash by removing the first and four last bytes of the decoded address, corresponding to
    # the version prefix and the checksum of the address.
    h160 = decoded_addr_hex[2:-8]

    return h160


def construct_unsigned_tx(txid, vout, address_send, address_dest, sats_hex_value, version="02000000", input_count="01",
                          output_count="01", locktime="00000000", sequence="ffffffff"):
    locking_script_send = create_1output_p2pkh(address_send)
    locking_script_send_length = hex(len(locking_script_send) // 2)[2:]

    locking_script_dest = create_1output_p2pkh(address_dest)
    locking_script_dest_length = hex(len(locking_script_dest) // 2)[2:]

    return (version + input_count + txid + vout), (locking_script_send_length + locking_script_send), (
            sequence + output_count + sats_hex_value + locking_script_dest_length + locking_script_dest + locktime)


def construct_signed_tx(unsigned_tx_a, unsigned_tx_b, unsigned_tx_c, sk_int, k=None):
    unsigned_tx = unsigned_tx_a + unsigned_tx_b + unsigned_tx_c
    unsigned_tx = Bitcoin.add_sigHashAll(unsigned_tx)

    tx_hash = Bitcoin.hash256(unsigned_tx)

    r, s = Bitcoin.sign_tx(sk_int, tx_hash, k)
    der_sig = Bitcoin.encode_sign_DER(r, s)
    der_sig = Bitcoin.append_sighash(der_sig)

    pk = Tools.calculate_compressed_pk(sk_int)

    unlocking_script = Bitcoin.script_sig(pk, der_sig)
    unlocking_script_length = hex(len(unlocking_script) // 2)[2:]

    return unsigned_tx_a + unlocking_script_length + unlocking_script + unsigned_tx_c
