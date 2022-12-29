# module for CSPRNG
import secrets

# -------------------------
# Elliptic Curve Parameters
# -------------------------
# y² = x³ + ax + b

a = 0
b = 7

# prime field
p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# number of points on the curve we can hit ("order")
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# generator point (the starting point on the curve used for all calculations)
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424


# ---------------
# Modular Inverse: Extended Euclidean Algorithm
# Esiste la funzione built-in pow(num,-1,primo)
# ---------------
def inverse(numero, primo=p):
    return pow(numero, -1, primo)


# ------
# Double: add a point to itself
# ------
def double(px, py):
    s = ((3 * px ** 2 + a) * inverse(2 * py)) % p
    px_double = (s ** 2 - 2 * px) % p
    py_double = (s * (px - px_double) - py) % p
    return px_double, py_double


# ---
# Add: add two points together
# ---
def add(p1x, p1y, p2x, p2y):
    # If p1 == p2 -> double(p1)
    if p1x == p2x and p1y == p2y:
        return double(p1x, p1y)

    s = ((p1y - p2y) * inverse(p1x - p2x)) % p
    px_add = (s ** 2 - p1x - p2x) % p
    py_add = (s * (p1x - px_add) - p1y) % p
    return px_add, py_add


# --------
# Multiply: use double and add operations to quickly multiply a point by an integer value (i.e. a private key)
# --------
def multiply(k, point_x=Gx, point_y=Gy):
    # create a copy of initial point
    current_x = point_x
    current_y = point_y

    # convert integer into binary representation
    binary_k = str(bin(k)[2:])  # [:2] to cut '0b' that python adds in the beginning

    # double & add algorithm for fast multiplication
    for i in range(1, len(binary_k)):  # start from binary_k[1] in order to avoid first element
        # 0 -> double
        current_x, current_y = double(current_x, current_y)

        # 1 -> & add
        if binary_k[i] == "1":
            current_x, current_y = add(current_x, current_y, point_x, point_y)

    return current_x, current_y


# --------
# SignMsg
# --------
def sign(private_key, msg_hash, k=None):
    # generate k if not given
    if k is None:
        k = secrets.randbelow(n)

    # generate point R = kG
    Rx, Ry = multiply(k)

    # generate the signature (r,s)
    r = Rx % n  # r is the coordinate_x mod n
    s = (inverse(k, n) * (int(msg_hash, 16) + private_key * r)) % n

    # choose the "low-s" value of s
    if s > n / 2:
        s = n - s

    return r, s


# --------
# VerifyMsg
# --------
def verify(public_key_x, public_key_y, msg_hash, r, s):
    # generate the two parts of the final equation
    first_addend_x, first_addend_y = multiply(inverse(s, n) * msg_hash)
    second_addend_x, second_addend_y = multiply(inverse(s, n) * r, public_key_x, public_key_y)

    # add the two points generated before in order to get R
    Rx, _ = add(first_addend_x, first_addend_y, second_addend_x, second_addend_y)
    return Rx == r
