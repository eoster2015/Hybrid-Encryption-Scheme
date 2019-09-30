import copy
import math

import gf256


# Converts from a UTF-8 encoded string into a list of 16 byte (128 bits) blocks represented by hexadecimal strings.
def string_to_blocks(str_input):
    str_list = list(str_input)
    block_length = int(math.ceil(128/8/4))
    while len(str_list) % block_length != 0:
        str_list.append(" ")
    num_blocks = int(len(str_list)//block_length)
    block_output = []
    for i in range(num_blocks):
        block_output.append([])
    k = 0
    for i in range(num_blocks):
        for j in range(block_length):
            current_char = ord(str_list[k])
            block_output[i].append(hex((current_char & 0xff000000) >> 24))
            block_output[i].append(hex((current_char & 0xff0000) >> 16))
            block_output[i].append(hex((current_char & 0xff00) >> 8))
            block_output[i].append(hex((current_char & 0xff)))
            k += 1
    return block_output


# Converts from a list of 16 byte (128 bits) blocks represented by hexadecimal strings into a UTF-8 encoded string.
def blocks_to_string(blocks_input):
    str_list = []
    flat_block = [item for sublist in blocks_input for item in sublist]
    for i in range(0, len(flat_block), 4):
        current_ord = (int(flat_block[i], 16) * 2**24) + (int(flat_block[i+1], 16) * 2**16) + \
                      (int(flat_block[i+2], 16) * 2**8) + int(flat_block[i+3], 16)
        current_char = chr(current_ord)
        str_list.append(current_char)
    str_output = ''.join(str_list)
    return str_output


# Converts from an ASCII encoded string into a list of 16 byte (128 bits) blocks represented by hexadecimal strings.
def string_to_blocks_ascii(str_input):
    str_list = list(str_input)
    block_length = int(math.ceil(128/8))
    while len(str_list) % block_length != 0:
        str_list.append(" ")
    num_blocks = int(len(str_list)//block_length)
    block_output = []
    for i in range(num_blocks):
        block_output.append([])
    k = 0
    for i in range(num_blocks):
        for j in range(block_length):
            block_output[i].append(hex(ord(str_list[k])))
            k += 1
    return block_output


# Converts from a list of 16 byte (128 bits) blocks represented by hexadecimal strings into an ASCII encoded string.
def blocks_to_string_ascii(blocks_input):
    str_list = []
    flat_block = [item for sublist in blocks_input for item in sublist]
    for i in range(len(flat_block)):
        current_char = chr(int(flat_block[i], 16))
        str_list.append(current_char)
    str_output = ''.join(str_list)
    return str_output


# Alternate string-to-block conversion to enable printing of ciphertext with invalid UTF-8 values to the string.
def hex_string_to_blocks(str_input):
    if isinstance(str_input, str) is False:
        str_input = str_input.decode('ascii')
    list_input = str_input.split(" ")
    input_length = len(list_input)
    num_blocks = input_length // 16
    block_output = []
    for i in range(num_blocks):
        block_output.append([])
    k = 0
    for i in range(num_blocks):
        for j in range(16):
            block_output[i].append(list_input[k])
            k += 1
    return block_output


# Alternate block-to-string conversion to enable printing of ciphertext with invalid UTF-8 values to the string.
def blocks_to_hex_string(blocks_input):
    str_list = [item for sublist in blocks_input for item in sublist]
    str_output = " ".join(str_list)
    return str_output


# Used to print 32-bit hex strings to simulate invalid UTF-8 characters in the ciphertext
def get_printable_hex_string(hex_input):
    hex_input_list = hex_input.split(' ')
    hex_output_list = []
    for i in range(0, len(hex_input_list), 4):
        hex_output_list.append("0x" +
                               hex_input_list[i].replace("0x", "").zfill(2) +
                               hex_input_list[i + 1].replace("0x", "").zfill(2) +
                               hex_input_list[i + 2].replace("0x", "").zfill(2) +
                               hex_input_list[i + 3].replace("0x", "").zfill(2))
    hex_output = " ".join(hex_output_list)
    return hex_output


# Reshapes a list into a square matrix.
def block_to_matrix(input_block, bit_length):
    dim = int(math.sqrt(math.ceil(bit_length/8)))
    output_matrix = [0] * dim
    for i in range(dim):
        output_matrix[i] = [0] * dim
    k = 0
    for i in range(dim):
        for j in range(dim):
            output_matrix[i][j] = input_block[k]
            k += 1
    return output_matrix


# Flattens a matrix into a list.
def matrix_to_block(input_matrix):
    output_block = [item for sublist in input_matrix for item in sublist]
    return output_block


# Performs a bitwise XOR on two blocks and returns a block.
def xor(block_input_1, block_input_2):
    i = 0
    block_output = []
    while i < len(block_input_1) and i < len(block_input_2):
        block_output.append(hex(int(block_input_1[i], 16) ^ int(block_input_2[i], 16)))
        i += 1
    return block_output


# Calls a library function to perform multiplication in the GF(2**8) galois field.
def galois_multiplication(hex_input_1, hex_input_2):
    if isinstance(hex_input_1, str):
        int1 = int(hex_input_1, 16)
    else:
        int1 = hex_input_1
    if isinstance(hex_input_2, str):
        int2 = int(hex_input_2, 16)
    else:
        int2 = hex_input_2
    gf_output = int(gf256.GF256(int1) * gf256.GF256(int2))
    return gf_output


# Used in generating the 240 byte expanded key for use in the key schedule.
def g_function(temp_word, rcon_iteration, et):
    temp = temp_word[0]
    for i in range(0, 3):
        temp_word[i] = temp_word[i + 1]
    temp_word[3] = temp
    for i in range(0,4):
        temp_word[i] = hex(et.get_sbox_value(int(temp_word[i], 16)))
    temp_word[0] = hex(int(temp_word[0], 16) ^ et.get_rcon_value(rcon_iteration))
    return temp_word


# Generates a 240 byte key schedule from the 256-bit secret key.
def get_expanded_key(key, et):
    key_list = list(key)
    for i in range(len(key_list)):
        key_list[i] = hex(ord(key_list[i]))
    expanded_key_list = []
    key_size = 32
    expanded_key_size = 240
    current_size = 0
    rcon_iteration = 1
    temp_word = [0x00] * 4
    for i in range(0, key_size):
        expanded_key_list.append(key_list[i])
    current_size += key_size
    while current_size < expanded_key_size:
        for i in range(0, 4):
            temp_word[i] = expanded_key_list[(current_size - 4) + i]
        if current_size % key_size == 0:
            temp_word = g_function(temp_word, rcon_iteration, et)
            rcon_iteration += 1
        if current_size % key_size == 16:
            for i in range(0, 4):
                temp_word[i] = hex(et.get_sbox_value(temp_word[i]))
        for i in range(0, 4):
            next_byte = hex(int(expanded_key_list[current_size - key_size], 16) ^ int(temp_word[i], 16))
            expanded_key_list.append(next_byte)
            current_size += 1
    return expanded_key_list


# Splits the 240 byte expanded key into 15 blocks of 16 bytes.
def get_key_schedule(expanded_key):
    key_schedule = [expanded_key[0:16], expanded_key[16:32], expanded_key[32:48], expanded_key[48:64],
                    expanded_key[64:80], expanded_key[80:96], expanded_key[96:112], expanded_key[112:128],
                    expanded_key[128:144], expanded_key[144:160], expanded_key[160:176], expanded_key[176:192],
                    expanded_key[192:208], expanded_key[208:224], expanded_key[224:240]]
    return key_schedule


# Performs the key addition layer operation, XORing the current block with the current key from the key schedule.
def key_addition_layer(matrix_input, current_key):
    current_key_matrix = block_to_matrix(current_key, 128)
    for i in range(4):
        for j in range(4):
            matrix_input[i][j] = hex(int(matrix_input[i][j], 16) ^ int(current_key_matrix[i][j], 16))
    return matrix_input


# Performs the byte substitution layer operation, substitutes matrix values with pre-calculated s-box values.
def byte_substitution_layer(matrix_input, et):
    for i in range(4):
        for j in range(4):
            matrix_input[i][j] = hex(et.get_sbox_value(matrix_input[i][j]))
    return matrix_input


# Performs the inverse of the byte substitution layer operation for decryption.
def inverse_byte_substitution_layer(matrix_input, et):
    for i in range(4):
        for j in range(4):
            matrix_input[i][j] = hex(et.get_rsbox_value(matrix_input[i][j]))
    return matrix_input


# Performs the shift row layer operation, shifting each row of the matrix a different number of bytes.
def shift_row_layer(matrix_input):
    matrix_input[1] = matrix_input[1][1:] + matrix_input[1][:1]
    matrix_input[2] = matrix_input[2][2:] + matrix_input[2][:2]
    matrix_input[3] = matrix_input[3][3:] + matrix_input[3][:3]
    return matrix_input


# Performs the inverse of the shift row layer operation for decryption.
def inverse_shift_row_layer(matrix_input):
    matrix_input[1] = matrix_input[1][-1:] + matrix_input[1][:-1]
    matrix_input[2] = matrix_input[2][-2:] + matrix_input[2][:-2]
    matrix_input[3] = matrix_input[3][-3:] + matrix_input[3][:-3]
    return matrix_input


# Performs the mix column layer operation by multiplying each column with a pre-calculated matrix.
# Note that in the galois finite field, XOR is identical to galois field addition.
def mix_column_layer(matrix_input):
    for i in range(4):
        copy_matrix = copy.deepcopy(matrix_input)
        matrix_input[0][i] = hex(
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x02) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x03)
                                )
        matrix_input[1][i] = hex(
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x02) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x03)
                                )
        matrix_input[2][i] = hex(
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x02) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x03)
                                )
        matrix_input[3][i] = hex(
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x02) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x01) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x03)
                                )
        copy_matrix = None
    return matrix_input


# Performs the inverse of the mix column layer operation for decryption.
def inverse_mix_column_layer(matrix_input):
    for i in range(4):
        copy_matrix = copy.deepcopy(matrix_input)
        matrix_input[0][i] = hex(
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x0e) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x09) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x0d) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x0b)
                                )
        matrix_input[1][i] = hex(
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x0e) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x09) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x0d) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x0b)
                                )
        matrix_input[2][i] = hex(
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x0e) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x09) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x0d) ^
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x0b)
                                )
        matrix_input[3][i] = hex(
                                galois_multiplication(int(copy_matrix[3][i], 16), 0x0e) ^
                                galois_multiplication(int(copy_matrix[2][i], 16), 0x09) ^
                                galois_multiplication(int(copy_matrix[1][i], 16), 0x0d) ^
                                galois_multiplication(int(copy_matrix[0][i], 16), 0x0b)
                                )
        copy_matrix = None
    return matrix_input


# Encrypts a single 128-bit block using AES-256.
def aes_block_encryption(block_input, key_schedule, et):
    matrix_input = block_to_matrix(block_input, 128)
    matrix_input = key_addition_layer(matrix_input, key_schedule[0])
    for i in range(1, 14):
        matrix_input = byte_substitution_layer(matrix_input, et)
        matrix_input = shift_row_layer(matrix_input)
        matrix_input = mix_column_layer(matrix_input)
        matrix_input = key_addition_layer(matrix_input, key_schedule[i])
    matrix_input = byte_substitution_layer(matrix_input, et)
    matrix_input = shift_row_layer(matrix_input)
    matrix_input = key_addition_layer(matrix_input, key_schedule[14])
    block_output = matrix_to_block(matrix_input)
    return block_output


# Decrypts a single 128-bit block using AES-256.
def aes_block_decryption(block_input, key_schedule, et):
    matrix_input = block_to_matrix(block_input, 128)
    matrix_input = key_addition_layer(matrix_input, key_schedule[14])
    matrix_input = inverse_shift_row_layer(matrix_input)
    matrix_input = inverse_byte_substitution_layer(matrix_input, et)
    for i in range(13, 0, -1):
        matrix_input = key_addition_layer(matrix_input, key_schedule[i])
        matrix_input = inverse_mix_column_layer(matrix_input)
        matrix_input = inverse_shift_row_layer(matrix_input)
        matrix_input = inverse_byte_substitution_layer(matrix_input, et)
    matrix_input = key_addition_layer(matrix_input, key_schedule[0])
    block_output = matrix_to_block(matrix_input)
    return block_output


# Encrypts plaintext using AES-256 running in the cipher blocking chaining operation mode.
def aes_encryption_cipher_block_chaining_mode(plaintext, key, iv, et):
    key = key[:32]
    expanded_key = get_expanded_key(key, et)
    key_schedule = get_key_schedule(expanded_key)
    plaintext_block_list = string_to_blocks(plaintext)
    ciphertext_block_list = []
    iv_block = string_to_blocks(iv)[0]
    first_block = xor(plaintext_block_list[0], iv_block)
    first_block_enc = aes_block_encryption(first_block, key_schedule, et)
    ciphertext_block_list.append(first_block_enc)
    for i in range(1, len(plaintext_block_list)):
        current_block = xor(plaintext_block_list[i], ciphertext_block_list[i - 1])
        ciphertext_block = aes_block_encryption(current_block, key_schedule, et)
        ciphertext_block_list.append(ciphertext_block)
    ciphertext = blocks_to_hex_string(ciphertext_block_list)
    return ciphertext


# Decrypts ciphertext using AES-256 running in the cipher blocking chaining operation mode.
def aes_decryption_cipher_block_chaining_mode(ciphertext, key, iv, et):
    key = key[:32]
    expanded_key = get_expanded_key(key, et)
    key_schedule = get_key_schedule(expanded_key)
    ciphertext_block_list = hex_string_to_blocks(ciphertext)
    plaintext_block_list = []
    iv_block = string_to_blocks(iv)[0]
    first_block_dec = aes_block_decryption(ciphertext_block_list[0], key_schedule, et)
    first_block = xor(first_block_dec, iv_block)
    plaintext_block_list.append(first_block)
    for i in range(1, len(ciphertext_block_list)):
        current_block = aes_block_decryption(ciphertext_block_list[i], key_schedule, et)
        plaintext_block = xor(current_block, ciphertext_block_list[i - 1])
        plaintext_block_list.append(plaintext_block)
    plaintext = blocks_to_string(plaintext_block_list)
    plaintext = plaintext.rstrip().lstrip()
    return plaintext
