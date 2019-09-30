import bg_methods as bg
import aes_methods as aes_m
import aes_objects as aes_o

import random
import string


class Person:

    def __init__(self, name, bit_length):
        self.name = name
        self.bg_bit_length = bit_length
        self.personal_aes_private_key = ''.join(
            random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
        self.personal_aes_iv = ''.join(
            random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
        self.aes_tables = aes_o.EncryptionTables()
        self.personal_bg_public_key, self.personal_bg_private_key = bg.bg_key_generation(self.bg_bit_length)

        self.partner_name = ""
        self.bg_public_key_received = ""
        self.aes_private_key_agreed = ""
        self.aes_iv_agreed = ""
        self.message_last_sent = "No message has been sent yet..."
        self.message_last_sent_cipher = ""
        self.message_last_sent_cipher_32_bit = "Therefore, there is no ciphertext yet either."
        self.message_last_received = "No message has been received yet..."
        self.message_last_received_cipher = ""
        self.message_last_received_cipher_32_bit = "Therefore, there is no ciphertext yet either."

    def generate_new_keys(self):
        self.personal_aes_private_key = ''.join(
            random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
        self.personal_bg_public_key, self.personal_bg_private_key = bg.bg_key_generation(self.bg_bit_length)

    def partner_request_connection(self):
        return self.name

    def partner_accept_connection(self, partner_name):
        self.partner_name = partner_name

    def partner_terminate_connection(self):
        self.partner_name = ""
        self.bg_public_key_received = ""
        self.aes_private_key_agreed = ""
        self.aes_iv_agreed = ""
        self.message_last_sent = "No message has been sent yet..."
        self.message_last_sent_cipher = ""
        self.message_last_sent_cipher_32_bit = "Therefore, there is no ciphertext yet either."
        self.message_last_received = "No message has been received yet..."
        self.message_last_received_cipher = ""
        self.message_last_received_cipher_32_bit = "Therefore, there is no ciphertext yet either."

    def send_bg_public_key(self):
        return self.personal_bg_public_key

    def receive_bg_public_key(self, bg_public_key):
        self.bg_public_key_received = bg_public_key

    def initiate_aes_key_agreement(self):
        self.aes_private_key_agreed, self.aes_iv_agreed = self.personal_aes_private_key, self.personal_aes_iv
        return (bg.bg_encryption(self.personal_aes_private_key, self.bg_public_key_received),
                bg.bg_encryption(self.personal_aes_iv, self.bg_public_key_received))

    def respond_aes_key_agreement(self, aes_key_agreement):
        aes_private_key_encrypted, aes_iv_encrypted = aes_key_agreement
        self.aes_private_key_agreed = bg.bg_decryption(aes_private_key_encrypted, self.personal_bg_private_key)
        self.aes_iv_agreed = bg.bg_decryption(aes_iv_encrypted, self.personal_bg_private_key)

    def send_encrypted_message(self, message):
        self.message_last_sent = message
        self.message_last_sent_cipher = \
            aes_m.aes_encryption_cipher_block_chaining_mode(message,
                                                            self.aes_private_key_agreed,
                                                            self.aes_iv_agreed, self.aes_tables)
        self.message_last_sent_cipher_32_bit= aes_m.get_printable_hex_string(self.message_last_sent_cipher)
        return self.message_last_sent_cipher

    def receive_encrypted_message(self, ciphertext):
        self.message_last_received_cipher = ciphertext
        self.message_last_received_cipher_32_bit = aes_m.get_printable_hex_string(self.message_last_received_cipher)
        self.message_last_received = \
            aes_m.aes_decryption_cipher_block_chaining_mode(ciphertext, self.aes_private_key_agreed,
                                                            self.aes_iv_agreed, self.aes_tables)
