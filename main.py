# module for CSPRNG
import secrets

# -------------------------
# Elliptic Curve Parameters
# -------------------------
# y² = x³ + ax + b

a = 0
b = 7

# prime field
p = 11

# number of points on the curve we can hit ("order")
n = 12

# generator point (the starting point on the curve used for all calculations)
Gx = 4
Gy = 4


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
    binary_k = str(bin(k)[2:])

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
    s = (inverse(k, n) * (msg_hash + private_key * r)) % n

    return r, s


x1, y1 = 2, 2
x2, y2 = 2, 2
sx, sy = add(x1,y1,x2,y2)
print(sx)
print(sy)

mx, my = multiply(3,4,4)
print(mx)
print(my)