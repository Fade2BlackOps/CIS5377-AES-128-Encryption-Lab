###    Name:    Vasil Ivanov III
###    File:    aes_lab.py
### Purpose:    AES-128 Encryption (and Opt. Decryption) Lab
###             with no standard encryption libraries allowed
###   Class:    Info. Security & Compliance
###    Prof:    Dr. Chengyi Qu
###     Due:    Tue. March 31, 2026
### ==================================================================
### Input format:
### - Plaintext: 16 ASCII characters
### - Key:       16 ASCII characters
### ==================================================================



## Arrays and Matrices:
## ---------------------------------------------------------------------------------------------------

# AES S-box
# Used in Step 2: SubBytes
# I turned it into a 2D array for easier indexing later
S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

# AES inverse S-box for optional decryption bonus
# I turned it into a 2D array for easier indexing later
INV_S_BOX = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

# Round constants
# Used in Step 0: Key Expansion
ROUND_CONSTANTS = [
    0x00,  # Round_Constants[0] is not used
    0x01, 0x02, 0x04, 0x08, 
    0x10, 0x20, 0x40, 0x80, 
    0x1B, 0x36
]



## Functions:
## ---------------------------------------------------------------------------------------------------

def print_matrix(matrix):
    """
    Print a 4x4 matrix in a readable hexadecimal format.
    """
    for row in matrix:                       # For each row in the matrix,
        for item in row:                     # for each item in the row,
            print(f"0x{item:02X}", end=" ")  # Print the item in hexadecimal format
        print()                              # Print a newline character after each row

def text_to_bytes(text):
    """
    Convert a 16-character ASCII string into a list of bytes.
    """
    return text.encode('utf-8')             # Encode the string into bytes using UTF-8 encoding

def bytes_to_state(byte_array):
    """
    Convert 16 bytes into a 4x4 AES state matrix.
    AES stores bytes column by column.
    """
    state = [[0] * 4 for _ in range(4)]     # Create an empty 4x4 matrix of 0's
    
    for i in range(len(byte_array)):
        row = i % 4                         # Row index cycles every 4 bytes
        column = i // 4                     # Column index increments every 4 bytes
        state[row][column] = byte_array[i]  # Fill the state matrix in column-major order

    return state

def state_to_bytes(state):
    """
    Convert a 4x4 AES state matrix back into bytes.
    """
    byte_array = []

    for column in range(4):
        for row in range(4):
            byte_array.append(state[row][column])

    return bytes(byte_array)

def xor_words(word1, word2):
    """
    XOR two 4-byte words together and return the result as a new word.
    This is used in key expansion.
    """
    return [word1[i] ^ word2[i] for i in range(4)]  # XOR each byte of the two words together


# Step 0: Key Expansion
def key_expansion(key_bytes):
    """
    Expand the original 16-byte key into 11 round keys.
    AES-128 requires 11 round keys total.

    Structure:
    1. Split original 16 bytes into 4 words
    2. While fewer than 44 words:
          temp = copy of previous word
          if word index % 4 == 0:
              temp = rotate_word(temp)
              temp = sub_word(temp)
              temp[0] ^= ROUND_CONSTANTS[round_number]
          new_word = xor_words(words[i-4], temp)
          append new_word
    3. Group every 4 words into one 4x4 round-key matrix
    4. Return list of 11 round-key matrices
    """
    # Step 1: Split original 16-byte key into 4 words
    words = []
    for i in range(0, 16, 4):
        words.append([key_bytes[i], key_bytes[i + 1], key_bytes[i + 2], key_bytes[i + 3]])

    # Step 2: Generate remaining words until we have 44 total
    for i in range(4, 44):
        temp = words[i - 1][:]   # copy previous word

        if i % 4 == 0:
            temp = rotate_word(temp)
            temp = sub_word(temp)
            temp[0] ^= ROUND_CONSTANTS[i // 4]

        new_word = xor_words(words[i - 4], temp)
        words.append(new_word)

    # Step 3: Group words into 11 round-key matrices
    round_keys = []

    for round_index in range(11):
        round_key = [[0] * 4 for _ in range(4)]

        for column in range(4):
            word = words[round_index * 4 + column]

            for row in range(4):
                round_key[row][column] = word[row]

        round_keys.append(round_key)

    return round_keys


# Step 1: AddRoundKey
def add_round_key(state, round_key):
    """
    XOR the current state with the round key.
    """
    for row in range(len(state)):                         # For each row in the state matrix,
        for column in range(len(state[row])):             # For each column in the row,
            state[row][column] ^= round_key[row][column]  # XOR the state byte with the corresponding round key byte

    return state


# We need a function to perform S-box substitution on 1 word (4 bytes) for key expansion.
def sub_word(word):
    """
    Substitute each byte in a 4-byte word using the AES S-box.
    """
    new_word = []                                       # Create a new list to hold the substituted bytes

    for byte in word:                                   # For each byte in the word,
        high_nibble = byte >> 4                             # Get the high nibble (first 4 bits)
        low_nibble = byte & 0x0F                            # Get the low nibble (last 4 bits)

        new_word.append(S_BOX[high_nibble][low_nibble])     # Substitute the byte using the S-box

    return new_word


# Step 2: SubBytes
def sub_bytes(state):
    """
    Replace each byte in the state using the AES S-box.
    """
    for row in range(len(state)):                                # For each row in the state matrix,
        for column in range(len(state[row])):                    # For each byte in the row,
            element = state[row][column]                         # Get the byte value from the state

            high_nibble = element >> 4                           # Get the high nibble (first 4 bits)
            low_nibble = element & 0x0F                          # Get the low nibble (last 4 bits)

            state[row][column] = S_BOX[high_nibble][low_nibble]  # Substitute the byte using the S-box

    return state


# To do Step 3, we need to rotate an array of bytes.
def rotate_word(word):
    """
    Rotate a 4-byte word left by 1 byte.
    Example: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
    """
    temp = word[0]                      # Store the first byte in a temporary variable
    for i in range(len(word) - 1):      # Shift the remaining bytes to the left
        word[i] = word[i + 1]
    word[-1] = temp                     # Place the first byte at the end of the word

    return word


# Step 3: ShiftRows
def shift_rows(state):
    """
    Shift the rows of the state to the left by their row index.
    Row 0: No shift
    Row 1: Shift left by 1
    Row 2: Shift left by 2
    Row 3: Shift left by 3
    """
    for row in range(len(state)):           # For each row in the state matrix,
        for _ in range(row):                # Shift the row left by its row index (0, 1, 2, or 3 times)
            rotate_word(state[row])         # Rotate the row left by its row index

    return state


# To do Step 4, we need to perform finite field multiplication, gmul.
def gmul(a, b):
    """
    Perform finite field multiplication of two bytes a and b.
    This is used in MixColumns, Step 4.
    Ref: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    """
    product = 0

    for _ in range(8):              # For each bit in b (up to 8 bits for a byte),
        if b & 1:                       # If the least significant bit of b is 1,
            product ^= a                # add a to the product (XOR in GF(2))

        high_bit_set = a & 0x80         # Check if the high bit of a is set (if a >= 128)
        a = (a << 1) & 0xFF             # Shift a left by 1 (multiply by x in GF(2))

        if high_bit_set:                # If the high bit of a was set before the shift,
            a ^= 0x1B                   # XOR a with the irreducible polynomial (0x1B) to reduce it
        
        b >>= 1                         # Shift b right by 1 to process the next bit

    return product


# Step 4: MixColumns
def mix_columns(state):
    """
    Mix each column of the state using AES finite field arithmetic.
    """
    for column in range(len(state[0])):     # For each column in the state matrix,
        a0 = state[0][column]                   # Get the bytes of the current column
        a1 = state[1][column]
        a2 = state[2][column]
        a3 = state[3][column]

        # Perform the MixColumns transformation using finite field multiplication
        # Matrix for multiplication:
        # | 02 03 01 01 |
        # | 01 02 03 01 |
        # | 01 01 02 03 |
        # | 03 01 01 02 |
        state[0][column] = gmul(0x02, a0) ^ gmul(0x03, a1) ^ a2 ^ a3    # (2·a0) XOR (3·a1) XOR a2 XOR a3
        state[1][column] = a0 ^ gmul(0x02, a1) ^ gmul(0x03, a2) ^ a3    # a0 XOR (2·a1) XOR (3·a2) XOR a3
        state[2][column] = a0 ^ a1 ^ gmul(0x02, a2) ^ gmul(0x03, a3)    # a0 XOR a1 XOR (2·a2) XOR (3·a3)
        state[3][column] = gmul(0x03, a0) ^ a1 ^ a2 ^ gmul(0x02, a3)    # (3·a0) XOR a1 XOR a2 XOR (2·a3)

    return state


# Main AES Encryption Function
def aes_encrypt(plaintext_bytes, key_bytes):
    """
    Encrypt a 16-byte block using AES-128.
    """
    state = bytes_to_state(plaintext_bytes)  # Convert plaintext bytes to state matrix
    round_keys = key_expansion(key_bytes)    # Generate round keys from the original key

    # Initial round (Round 0)
    add_round_key(state, round_keys[0])      # AddRoundKey with the first round key

    # Rounds 1-9
    for round_num in range(1, 10):
        sub_bytes(state)                             # SubBytes
        shift_rows(state)                            # ShiftRows
        mix_columns(state)                           # MixColumns
        add_round_key(state, round_keys[round_num])  # AddRoundKey with the current round key
    
    # Final round (Round 10, no MixColumns)
    sub_bytes(state)                                 # SubBytes
    shift_rows(state)                                # ShiftRows
    add_round_key(state, round_keys[10])             # AddRoundKey with the final round key

    return state_to_bytes(state)                     # Convert the final state matrix back to bytes


# Main Function:
def main():
    # Get user input for plaintext and key
    plaintext = input("Enter 16-character plaintext: ")
    key = input("Enter 16-character key: ")

    # # Validate input lengths
    # if len(plaintext) != 16:
    #     print("Error: Plaintext must be exactly 16 characters long.")
    #     return

    # if len(key) != 16:
    #     print("Error: Key must be exactly 16 characters long.")
    #     return

    # # Convert inputs to bytes
    # plaintext_bytes = text_to_bytes(plaintext)
    # key_bytes = text_to_bytes(key)

    # # Encrypt the plaintext
    # ciphertext = aes_encrypt(plaintext_bytes, key_bytes)

    # # Print the ciphertext in hexadecimal format
    # print("Plaintext    :", plaintext)
    # print("Key          :", key)
    # print("Ciphertext (hex):", ciphertext.hex())

    state = bytes_to_state(text_to_bytes(plaintext))
    key_state = bytes_to_state(text_to_bytes(key))

    round_keys = key_expansion(text_to_bytes(key))

    print("\nRound Key 0:")
    print_matrix(round_keys[0])

    print("\nRound Key 1:")
    print_matrix(round_keys[1])

    print("\nInitial State:")
    print_matrix(state)

    print("\nInitial Key State:")
    print_matrix(key_state)

    add_round_key(state, key_state)
    print("\nAfter AddRoundKey:")
    print_matrix(state)

    sub_bytes(state)
    print("\nAfter SubBytes:")
    print_matrix(state)

    shift_rows(state)
    print("\nAfter ShiftRows:")
    print_matrix(state)

    # DEBUG: Let's sanity check: test prints here...
    print("\nTesting gmul function:")
    print(hex(gmul(0x57, 0x13)))  # expected: 0xfe
    print(hex(gmul(0x02, 0x53)))  # expected: 0xa6
    print(hex(gmul(0x03, 0x53)))  # expected: 0xf5

    mix_columns(state)
    print("\nAfter MixColumns:")
    print_matrix(state)


if __name__ == "__main__":
    main()