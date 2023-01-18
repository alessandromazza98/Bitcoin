import hashlib
import secrets
from ECDSAUnit import multiply, add, n, p


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def hash_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")


def tagged_hash(tag, data_bytes):
    return hash_sha256(hash_sha256(tag.encode()) + hash_sha256(tag.encode()) + data_bytes)


def ser256_schnorr(P):
    return bytes_from_int(P[0])


def lift_x(x: int):
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return x, y if y & 1 == 0 else p - y


def sign_schnorr(private_key_int, msg_hash_bytes, k=None):
    P = multiply(private_key_int)
    if not P[1] % 2 == 0:
        private_key_int = n - private_key_int

    if k is None:
        k = secrets.randbelow(n)

    R = multiply(k)
    if not R[1] % 2 == 0:
        k = n - k

    e = int_from_bytes(tagged_hash("BIP0340/challenge", ser256_schnorr(R) + ser256_schnorr(P) + msg_hash_bytes))

    sig = ser256_schnorr(R), bytes_from_int((k + e * private_key_int) % n)
    return sig


def verify_schnorr(sig, msg_bytes, P_ser256_bytes):
    R_ser256_bytes, s = sig

    P = lift_x(int_from_bytes(P_ser256_bytes))
    e = int_from_bytes(tagged_hash("BIP0340/challenge", R_ser256_bytes + P_ser256_bytes + msg_bytes)) % n

    s_int = int_from_bytes(s)
    R = add(multiply(s_int), multiply(n - e, P))

    if not R[1] % 2 == 0:
        return False

    r_int = int_from_bytes(R_ser256_bytes)
    if R[0] != r_int:
        return False
    return True
