#!/usr/bin/env python3

import sys

import aes_methods as aes_m
import aes_objects as aes_o


def main():
    et = aes_o.EncryptionTables()
    test_key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    print("Test Key:\t", test_key)
    test_key = test_key[:32]
    expanded_key_list = aes_m.get_expanded_key(test_key, et)
    print("Expanded Key:\t\t", expanded_key_list)
    print("Expanded Key Length:", len(expanded_key_list), "bytes")
    key_schedule = aes_m.get_key_schedule(expanded_key_list)
    print("Key Schedule:\t\t", key_schedule)
    print("Key Schedule Length:", len(key_schedule), "blocks of 128 bits")
    print("k14 List:\t", key_schedule[14])
    matrix_test = aes_m.block_to_matrix(key_schedule[14], 128)
    print("k14 Matrix:", matrix_test)
    string_to_blocks_test = aes_m.string_to_blocks("Testing block and string conversions... completed!")
    blocks_to_string_test = aes_m.blocks_to_string(string_to_blocks_test)
    print(blocks_to_string_test)
    test_input_text = "She said don't make others suffer for your personal hatred."
    test_key = "6SJ5Y0sUC0igZXs9rUvUneFfGZoWjKEZ"
    test_iv = "2357111317192329"
    print("\nTest Key: ", test_key)
    print("Test Initialization Vector: ", test_iv)
    print("\nTest Plaintext Input:\n", test_input_text)
    test_cbc_encryption = aes_m.aes_encryption_cipher_block_chaining_mode(test_input_text, test_key, test_iv, et)
    print("\nTest of AES-256 Encryption in Cipher Block Chaining Operation Mode:\n", test_cbc_encryption)
    test_cbc_decryption = aes_m.aes_decryption_cipher_block_chaining_mode(test_cbc_encryption, test_key, test_iv, et)
    print("\nTest of AES-256 Decryption in Cipher Block Chaining Operation Mode:\n", test_cbc_decryption)
    print("\nAES-256 testing successfully completed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
