import numpy as np
import hmac
import hashlib
import binascii


class EncryptionProcess:
    s_box = {
        "0000": "0101",
        "0001": "0111",
        "0010": "1101",
        "0011": "1001",
        "0100": "1011",
        "0101": "1110",
        "0110": "1100",
        "0111": "1010",
        "1000": "1111",
        "1001": "0010",
        "1010": "0100",
        "1011": "0001",
        "1100": "1000",
        "1101": "0000",
        "1110": "0110",
        "1111": "0011"
    }

    def __init__(self):
        text = input("Enter your text: ")
        IK = input("Enter your secret message: ")
        salt = input("Enter your salt message: ")
        L = 16  # 128-bit key length
        info = "OutputKey_"

        # Convert text to binary
        binary_str = ''.join(format(ord(char), '08b') for char in text)
        PRK = self.HKDF_Extract(IK, salt)
        output_keys = self.HKDF_Expand(PRK, info, L, 7)  # Generating 7 keys
        k = 0
        string = ""
        while k < len(binary_str):
            mat = [[0 for _ in range(8)] for _ in range(16)]
            for i in range(16):
                for j in range(8):
                    if k < len(binary_str):
                        mat[i][j] = int(binary_str[k])
                        k += 1

            transposed_matrix = np.array(mat).T.tolist()
            # Perform operations on the matrix
            for i in range(0, 7):
                transposed_matrix = self.permutation_matrix(transposed_matrix)
                transposed_matrix = self.substitution_matrix(transposed_matrix)
                transposed_matrix = self.transformation_matrix(transposed_matrix)
                transposed_matrix = self.function_box(i, IK, salt, info, L, transposed_matrix, output_keys[i])
                transposed_matrix = self.permutation_matrix(transposed_matrix)
            for i in range(0, 8):
                for j in range(0, 16):
                    string += str(transposed_matrix[i][j])

        print("Ciphertext: ")
        #print(string)
        string = string.replace(" ", "")
        print(self.binary_to_text(string))

    @staticmethod
    def binary_to_text(binary_string):
        return ''.join(chr(int(binary_string[i:i + 8], 2)) for i in range(0, len(binary_string), 8))

    @staticmethod
    def HKDF_Extract(IK, salt):
        return hmac.new(salt.encode('utf-8'), IK.encode('utf-8'), hashlib.sha256).digest()

    @staticmethod
    def HKDF_Expand(PRK, info, L, num_keys):
        output_key = []
        T = b""
        for i in range(num_keys):
            T = hmac.new(PRK, T + info.encode('utf-8') + bytes([i + 1]), hashlib.sha256).digest()
            output_key.append(T[:L])
        return output_key

    @staticmethod
    def shift_up(matrix):
        # Shift up operation
        shifted_matrix = np.roll(matrix, -1, axis=0)
        return shifted_matrix

    @staticmethod
    def shift_right(matrix):
        # Shift right operation
        shifted_matrix = np.roll(matrix, -1, axis=1)
        return shifted_matrix

    @staticmethod
    def permutation_matrix(matrix):
        matrix = EncryptionProcess.shift_up(matrix)
        matrix = EncryptionProcess.shift_right(matrix)
        matrix = EncryptionProcess.shift_up(matrix)
        return matrix

    @staticmethod
    def substitution_matrix(matrix):
        # Placeholder for actual substitution
        for i in range(0, 16):
            string = ""
            string += str(matrix[0][i])
            string += str(matrix[1][i])
            string += str(matrix[2][i])
            string += str(matrix[3][i])
            string = EncryptionProcess.s_box.get(string)
            h = 0
            for h in range(0, 4):
                matrix[h][i] = string[h]
            string = ""
            string += str(matrix[4][i])
            string += str(matrix[5][i])
            string += str(matrix[6][i])
            string += str(matrix[7][i])
            string = EncryptionProcess.s_box.get(string)
            h = 4
            for h in range(0, 4):
                matrix[h + 4][i] = string[h]

        return matrix

    @staticmethod
    def transformation_matrix(matrix):
        matrix = 1 - matrix
        return matrix

    @staticmethod
    def function_box(i, IK, salt, info, L, matrix, output_key):
        # output_key =  # Select the appropriate key
        key_binary_str = ''.join(format(byte, '08b') for byte in output_key)

        key_matrix = np.array([int(bit) for bit in key_binary_str]).reshape(matrix.shape)
        matrix = np.bitwise_xor(key_matrix, matrix)
        matrix = EncryptionProcess.transformation_matrix(matrix)
        return matrix


class DecryptionProcess:
    s_box = {
        "0000": "1101",
        "0001": "1011",
        "0010": "1001",
        "0011": "1111",
        "0100": "1010",
        "0101": "0000",
        "0110": "1110",
        "0111": "0001",
        "1000": "1100",
        "1001": "0011",
        "1010": "0111",
        "1011": "0100",
        "1100": "0110",
        "1101": "0010",
        "1110": "0101",
        "1111": "1000"
    }

    def __init__(self):
        text = input("Enter your ciphertext: ")
        IK = input("Enter your secret message: ")
        salt = input("Enter your salt message: ")
        L = 16  # 128-bit key length
        info = "OutputKey_"
        PRK = self.HKDF_Extract(IK, salt)
        output_keys = self.HKDF_Expand(PRK, info, L, 7)  # Generating 7 keys
        # Convert text to binary
        text = ''.join(format(ord(char), '08b') for char in text)
        k = 0
        string = ""
        while k < len(text):
            transposed_matrix = [[0 for _ in range(16)] for _ in range(8)]
            for i in range(8):
                for j in range(16):
                    if k < len(text):
                        transposed_matrix[i][j] = int(text[k])
                        k += 1

            # Perform operations on the matrix
            h = 6
            for i in range(0, 7):
                transposed_matrix = self.permutation_matrix(transposed_matrix)
                transposed_matrix = self.function_box(transposed_matrix, output_keys[h])
                h -= 1
                transposed_matrix = self.transformation_matrix(transposed_matrix)
                transposed_matrix = self.substitution_matrix(transposed_matrix)
                transposed_matrix = self.permutation_matrix(transposed_matrix)
            for i in range(0, 16):
                for j in range(0, 8):
                    string += str(transposed_matrix[j][i])
        print("Plaintext: ")
        # print(string)
        string = string.replace(" ", "")
        print(self.binary_to_text(string))

    @staticmethod
    def binary_to_text(binary_string):
        return ''.join(chr(int(binary_string[i:i + 8], 2)) for i in range(0, len(binary_string), 8))

    @staticmethod
    def HKDF_Extract(IK, salt):
        return hmac.new(salt.encode('utf-8'), IK.encode('utf-8'), hashlib.sha256).digest()

    @staticmethod
    def HKDF_Expand(PRK, info, L, num_keys):
        output_key = []
        T = b""
        for i in range(num_keys):
            T = hmac.new(PRK, T + info.encode('utf-8') + bytes([i + 1]), hashlib.sha256).digest()
            output_key.append(T[:L])
        return output_key

    @staticmethod
    def shift_down(matrix):
        # Shift down operation
        shifted_matrix = np.roll(matrix, 1, axis=0)
        return shifted_matrix

    @staticmethod
    def shift_left(matrix):
        # Shift left operation
        shifted_matrix = np.roll(matrix, 1, axis=1)
        return shifted_matrix

    @staticmethod
    def permutation_matrix(matrix):
        matrix = DecryptionProcess.shift_down(matrix)
        matrix = DecryptionProcess.shift_left(matrix)
        matrix = DecryptionProcess.shift_down(matrix)
        return matrix

    @staticmethod
    def substitution_matrix(matrix):
        # Placeholder for actual substitution
        for i in range(0, 16):
            string = ""
            string += str(matrix[0][i])
            string += str(matrix[1][i])
            string += str(matrix[2][i])
            string += str(matrix[3][i])
            string = DecryptionProcess.s_box.get(string)
            h = 0
            for h in range(0, 4):
                matrix[h][i] = string[h]
            string = ""
            string += str(matrix[4][i])
            string += str(matrix[5][i])
            string += str(matrix[6][i])
            string += str(matrix[7][i])
            string = DecryptionProcess.s_box.get(string)
            h = 4
            for h in range(0, 4):
                matrix[h + 4][i] = string[h]

        return matrix

    @staticmethod
    def transformation_matrix(matrix):
        matrix = 1 - matrix
        return matrix

    @staticmethod
    def function_box(matrix, output_key):
        matrix = DecryptionProcess.transformation_matrix(matrix)

        # output_key = output_key # Select the appropriate key
        key_binary_str = ''.join(format(byte, '08b') for byte in output_key)

        key_matrix = np.array([int(bit) for bit in key_binary_str]).reshape(matrix.shape)

        matrix = np.bitwise_xor(key_matrix, matrix)
        return matrix


if __name__ == "__main__":
    print("Welcome")
    
    choice = input("What operation would you like to perform\n 1. Encryption\n 2. Decryption\n 3. Quit\n")
    while choice != '3':
        if choice == '1' or choice == "Encryption" or choice == "encryption":
            EncryptionProcess()
        elif choice == '2' or choice == "Decryption" or choice == "decryption":
            DecryptionProcess()
        else:
            print("Select from the above options")
        choice = input("What operation would you like to perform\n 1. Encryption\n 2. Decryption\n 3. Quit\n")
        
    print("Thank You")
            
