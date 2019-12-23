import re
import sys

import models as m


def simulator_setup():
    print("***********************************************")
    print("Welcome to the Secure Communications Simulator!")
    print("***********************************************")
    print("Message encryption performed by a custom hybrid cryptosystem\nutilizing AES-256 and Blum-Goldwasser.\n")
    person1_name = input("Please enter a name for the first participant: ")
    while len(person1_name) < 1:
        print("Error: please enter at least one character.")
        person1_name = input("Please enter a name for the first participant: ")
    person1_name = re.sub(r'\W+', ' ', person1_name)
    person1_bits = input("How many bits should they use for their Blum-Goldwasser public key? ")
    while person1_bits.isdigit() is False or int(person1_bits) < 256 or int(person1_bits) > 2048:
        print("Error: number of bits must be a positive integer no less than 256 to ensure brute-force resistance " +
              "and no greater than 2048 due to computational power limitations.")
        person1_bits = input("How many bits should they use for their Blum-Goldwasser public key? ")
    person1_bits = int(person1_bits)
    person2_name = input("Please enter a name for the second participant: ")
    if len(person2_name) < 1:
        print("Error: please enter at least one character.")
        person2_name = input("Please enter a name for the second participant: ")
    person2_name = re.sub(r'\W+', ' ', person2_name)
    person2_bits = input("How many bits should they use for their Blum-Goldwasser public key? ")
    while person2_bits.isdigit() is False or int(person2_bits) < 256 or int(person2_bits) > 2048:
        print("Error: number of bits must be a positive integer no less than 256 to ensure brute-force resistance " +
              "and no greater than 2048 due to computational power limitations.")
        person2_bits = input("How many bits should they use for their Blum-Goldwasser public key? ")
    person2_bits = int(person2_bits)
    person1 = m.Person(person1_name, person1_bits)
    person2 = m.Person(person2_name, person2_bits)
    initialize_connection(person1, person2)
    print("\nKey Values:\n")
    print(person1.name + " Blum-Goldwasser public key:\n" + str(person1.personal_bg_public_key) + "\n")
    print(person1.name + " Blum-Goldwasser private key:\n" + str(person1.personal_bg_private_key) + "\n")
    print(person2.name + " Blum-Goldwasser public key:\n" + str(person2.personal_bg_public_key) + "\n")
    print(person2.name + " Blum-Goldwasser private key:\n" + str(person2.personal_bg_private_key) + "\n")
    print("Agreement established for AES Private Key:\n" + str(person1.aes_private_key_agreed) + "\n")
    print("Initialization vector for AES:\n" + str(person1.aes_iv_agreed))
    return person1, person2


def display_menu(person1, person2):
    print()
    print("***************************************************")
    print("Please select an option from the following choices:")
    print("***************************************************")
    print("1 = Send a message from ", person1.name, " to ", person1.partner_name, ".", sep="")
    print("2 = Send a message from ", person2.name, " to ", person2.partner_name, ".", sep="")
    print("3 = Print the message last received by ", person2.name, ".", sep="")
    print("4 = Print the message last received by ", person1.name, ".", sep="")
    print("5 = Print the message last sent by ", person1.name, ".", sep="")
    print("6 = Print the message last sent by ", person2.name, ".", sep="")
    print("7 = Update participants' encryption keys.")
    print("8 = Restart the simulator.")
    print("9 = Exit the simulator")
    print("***************************************************")
    print()


def initialize_connection(person1, person2):
    person1.partner_accept_connection(person2.partner_request_connection())
    person2.partner_accept_connection(person1.partner_request_connection())
    person2.receive_bg_public_key(person1.send_bg_public_key())
    person1.receive_bg_public_key(person2.send_bg_public_key())
    person1.respond_aes_key_agreement(person2.initiate_aes_key_agreement())
    print("\nInitialized connection between ", person1.name, " and ", person2.name, ".", sep="")
    return


def message_transfer(sender, receiver, message):
    encrypted_message = sender.send_encrypted_message(message)
    receiver.receive_encrypted_message(encrypted_message)


def update_keys(person1, person2):
    person1.partner_terminate_connection()
    person2.partner_terminate_connection()
    person1.generate_new_keys()
    person2.generate_new_keys()
    person1.partner_accept_connection(person2.partner_request_connection())
    person2.partner_accept_connection(person1.partner_request_connection())
    person2.receive_bg_public_key(person1.send_bg_public_key())
    person1.receive_bg_public_key(person2.send_bg_public_key())
    person1.respond_aes_key_agreement(person2.initiate_aes_key_agreement())
    print("\nKeys have been refreshed for ", person1.name, " and ", person2.name, ".", sep="")


def terminate_connection(person1, person2):
    person1.partner_terminate_connection()
    person2.partner_terminate_connection()
    print("\nTerminated connection between ", person1.name, " and ", person2.name, ".", sep="")


def restart_simulator(person1, person2):
    terminate_connection(person1, person2)
    print("Restarting Secure Communications Simulator now...\n")
    newperson1, newperson2 = simulator_setup()
    return newperson1, newperson2


def exit_simulator(person1, person2):
    terminate_connection(person1, person2)
    print("Now exiting the Secure Communications Simulator! Goodbye!")
    sys.exit(0)
