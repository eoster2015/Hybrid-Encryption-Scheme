import math
import secrets


# Implementation of Square-and-Multiply fast modular exponentiation function.
# Make sure that every argument passed to this function is an integer to avoid floating-point errors.
def mod_exp_sam(base, exponent, modulus):
    k = bin(exponent)
    b = 1
    if exponent == 0:
        return b
    a = base
    if k[-1] == '1':
        b = a
    i = -2
    while k[i] != 'b':
        a = a**2 % modulus
        if k[i] == '1':
            b = a * b % modulus
        i -= 1
    return b


# Implementation of the Miller-Rabin primality test.
# The recommended number of rounds for the security parameter is 40.
def miller_rabin_test(num, security_parameter):
    r = num - 1
    s = 0
    # equivalent to r % 2 == 0
    while r & 1 == 0:
        # equivalent to r //= 2
        r >>= 1
        s += 1
    for i in range(security_parameter):
        a = secrets.randbelow(num - 1)
        while a <= 2:
            a = secrets.randbelow(num - 1)
        y = mod_exp_sam(a, r, num)
        if y != 1 and y != num - 1:
            j = 1
            while j <= s - 1 and y != num - 1:
                # since Square-and-Multiply fast modular exponentiation contains the line "a = a**2 % modulus"
                # for an exponent of 2 it would be slower to call than just calculating y**2 % num
                y = y**2 % num
                y = mod_exp_sam(y, 2, num)
                if y == 1:
                    return False
                j += 1
            if y != num - 1:
                return False
    return True


# Generates random integers of a specified bit length until the Miller-Rabin primality test returns true.
def get_large_prime_3_mod_4(bit_length):
    bit_length = int(bit_length)
    while True:
        rand_num = secrets.randbits(bit_length)
        if rand_num % 4 != 3 \
                or rand_num % 3 == 0 or rand_num % 5 == 0 or rand_num % 7 == 0 or rand_num % 11 == 0\
                or miller_rabin_test(rand_num, 40) is False:
            continue
        return rand_num


# Performs the Extended Euclidean Algorithm to get the Bézout coefficients for two prime numbers.
# Because the two integers passed to this function will always be prime, GCD(p, q) will always be 1.
def eea_prime(p, q):
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = q, p
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s, old_t


# Generates a random quadratic residue mod n.
def random_quad_residue(n):
    while True:
        rand_num = secrets.randbelow(n)
        if rand_num < 3:
            continue
        else:
            break
    quad_residue = rand_num**2 % n
    return quad_residue


# Generates the public key and private key tuple for the Blum-Goldwasser encryption scheme.
def bg_key_generation(bit_length):
    bit_length = int(bit_length)
    p = get_large_prime_3_mod_4(bit_length)
    q = get_large_prime_3_mod_4(bit_length)
    n = p * q
    public_key = n
    a, b = eea_prime(p, q)
    private_key = (p, q, a, b)
    return public_key, private_key


# Encrypts ASCII plaintext using the Blum-Goldwasser probabilistic public-key encryption scheme.
def bg_encryption(message, public_key):
    binary_message = list(map(bin, bytearray(message, encoding='ascii')))
    for i in range(len(binary_message)):
        binary_message[i] = binary_message[i].replace("0b", "")
        if len(binary_message[i]) != 8:
            binary_message[i] = binary_message[i].zfill(8)
    m = "".join(binary_message)
    m_length = len(m)
    n = public_key
    k = int(math.floor(math.log(n, 2)))
    h = int(math.floor(math.log(k, 2)))
    mask = 2**h - 1
    while m_length % h != 0:
        m += "0"
        m_length += 1
    m_list = []
    for i in range(0, m_length, h):
        m_list.append(m[i:i+h])
    t = len(m_list)
    x0 = random_quad_residue(n)
    x_list = [x0**2 % n]
    p_list = [x_list[0] & mask]
    c_list = [int(m_list[0], 2) ^ p_list[0]]
    for i in range(1, t):
        x_list.append(x_list[i - 1]**2 % n)
        p_list.append(x_list[i] & mask)
        c_list.append(int(m_list[i], 2) ^ p_list[i])
    ciphertext = c_list
    ciphertext.append(x_list[-1]**2 % n)
    return ciphertext


# Decrypts ASCII ciphertext that was encrypted using the Blum-Goldwasser probabilistic public-key encryption scheme.
def bg_decryption(ciphertext, private_key):
    p, q, a, b = private_key
    n = p * q
    k = int(math.floor(math.log(n, 2)))
    h = int(math.floor(math.log(k, 2)))
    mask = 2**h - 1
    xt1 = ciphertext[-1]
    c_list = ciphertext[:-1]
    t = len(c_list)
    d1 = mod_exp_sam((p + 1) // 4, t + 1, p - 1)
    d2 = mod_exp_sam((q + 1) // 4, t + 1, q - 1)
    u = mod_exp_sam(xt1, d1, p)
    v = mod_exp_sam(xt1, d2, q)
    x0 = (v * a * p + u * b * q) % n
    x_list = [x0 ** 2 % n]
    p_list = [x_list[0] & mask]
    m_list = [c_list[0] ^ p_list[0]]
    for i in range(1, t):
        x_list.append(x_list[i - 1]**2 % n)
        p_list.append(x_list[i] & mask)
        m_list.append(c_list[i] ^ p_list[i])
    # Converting from binary back into ASCII encoded string
    binary_list = m_list
    for i in range(len(binary_list)):
        binary_list[i] = bin(binary_list[i])
        binary_list[i] = binary_list[i].replace("0b", "")
        # Pad the length of each substring to the length of h to ensure uniform block size
        if len(binary_list[i]) < h:
            binary_list[i] = binary_list[i].zfill(h)
    binary_message = "".join(binary_list)
    extra_char_num = len(binary_message) % 8
    if extra_char_num != 0:
        binary_message = binary_message[:-extra_char_num]
    binary_list = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
    message = ""
    for i in range(len(binary_list)):
        current_char = chr(int(binary_list[i], 2))
        message += current_char
    return message
