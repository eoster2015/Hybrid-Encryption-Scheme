#!/usr/bin/env python3

import sys

import bg_methods as bg


def main():
    print("Testing Blum-Goldwasser methods...\n")
    print("Square-and-Multiply modular exponentiation test: 11^13 mod(19) =", bg.mod_exp_sam(11, 13, 19))
    print("Rabin-Miller Primality Test: Is 59 prime?", bg.miller_rabin_test(59, 40))
    a, b = 23, 59
    s, t = bg.eea_prime(a, b)
    print("Extended Euclidean Algorithm Test: The Bézout coefficients for a =", a, "and b =", b, "are s =", s, "and t =", t)
    print("\tVerification:", s, "*", a, "+", t, "*", b, "=", s * a + t * b)
    print("\nTesting Blum-Goldwasser probabilistic public-key encryption scheme using 512-bit prime numbers...")
    test_public_key, test_private_key = bg.bg_key_generation(512)
    test_message = "The real treasure was the friends we made along the way!"
    print("\nTest Public Key:\n", test_public_key)
    print("\nTest Private Key:\n", test_private_key)
    print("\nTest Plaintext Input:\n", test_message)
    test_bg_encryption = bg.bg_encryption(test_message, test_public_key)
    print("\nTest of Blum-Goldwasser Encryption:\n", test_bg_encryption)
    test_bg_decryption = bg.bg_decryption(test_bg_encryption, test_private_key)
    print("\nTest of Blum-Goldwasser Decryption:\n", test_bg_decryption)
    print("\nBlum-Goldwasser testing successfully completed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
