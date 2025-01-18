from EncryptionProcess import EncryptionProcess
from DecryptionProcess import DecryptionProcess

if __name__ == "__main__":
    print("Welcome")
    choice = input("What operation would you like to perform\n 1. Encryption\n 2. Decryption\n 3. Quit\n")
    while choice != '3':
        if choice == '1':
            EncryptionProcess()
        elif choice == '2':
            DecryptionProcess()
        else:
            print("Select from the above options")
        choice = input("What operation would you like to perform\n 1. Encryption\n 2. Decryption\n 3. Quit\n")
    print("Thank You")
