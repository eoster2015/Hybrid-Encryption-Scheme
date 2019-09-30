#!/usr/bin/env python3

import io_methods as scs


def main():
    person1, person2 = scs.simulator_setup()
    while True:
        scs.display_menu(person1, person2)
        choice = input("Selection: ")
        if len(choice) < 1:
            print("Error: selection not recognized. Please enter another selection.")
        elif choice[0] == "1":
            print("\nPlease enter a message to send to ", person2.name, ":", sep="")
            message = input()
            scs.message_transfer(person1, person2, message)
            print(person2.name, " received the following message: \"", person2.message_last_received, "\"", sep="")
        elif choice[0] == "2":
            print("\nPlease enter a message to send to ", person1.name, ":", sep="")
            message = input()
            scs.message_transfer(person2, person1, message)
            print(person1.name, " received the following message: \"", person1.message_last_received, "\"", sep="")
        elif choice[0] == "3":
            print("\nThe ciphertext last received by ", person2.name, " was \"",
                  person2.message_last_received_cipher_32_bit, "\"", sep="")
            print("\nThe corresponding decrypted message last received by ", person2.name, " was \"",
                  person2.message_last_received, "\"", sep="")
        elif choice[0] == "4":
            print("\nThe ciphertext last received by ", person1.name, " was \"",
                  person1.message_last_received_cipher_32_bit, "\"", sep="")
            print("\nThe corresponding decrypted message last received by ", person1.name, " was \"",
                  person1.message_last_received, "\"", sep="")
        elif choice[0] == "5":
            print("\nThe ciphertext last sent by ", person1.name, " was \"",
                  person1.message_last_sent_cipher_32_bit, "\"", sep="")
            print("\nThe corresponding decrypted message last sent by ", person1.name, " was \"",
                  person1.message_last_sent, "\"", sep="")
        elif choice[0] == "6":
            print("\nThe ciphertext last sent by ", person2.name, " was \"",
                  person2.message_last_sent_cipher_32_bit, "\"", sep="")
            print("\nThe corresponding decrypted message last sent by ", person2.name, " was \"",
                  person2.message_last_sent, "\"", sep="")
        elif choice[0] == "7":
            scs.update_keys(person1, person2)
        elif choice[0] == "8":
            person1, person2 = scs.restart_simulator(person1, person2)
        elif choice[0] == "9":
            scs.exit_simulator(person1, person2)
        else:
            print("Error: selection not recognized. Please enter another selection.")


if __name__ == "__main__":
    main()
