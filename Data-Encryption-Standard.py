# -------------------------- DES Implementation from Scratch --------------------------
# This program performs both encryption and decryption without using built-in DES functions.

# -------------------------- Helper Functions --------------------------

# Permutation function: rearranges bits according to a table
def permute(bits, table):
    # bits: list of 0s and 1s
    # table: permutation table
    # returns permuted bits according to table
    return [bits[i-1] for i in table]

# Left shift function for key scheduling
def left_shift(bits, n):
    # shifts bits to the left by n positions
    return bits[n:] + bits[:n]

# XOR two bit lists
def xor(bits1, bits2):
    # XOR operation between two bit lists
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# Convert string to bit array
def string_to_bits(text):
    # converts each character into 8-bit binary
    bits = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')  # get 8-bit binary
        bits.extend([int(x) for x in binval])
    return bits

# Convert bit array to string
def bits_to_string(bits):
    # converts every 8 bits back to character
    text = ''
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        text += chr(int(''.join(str(b) for b in byte), 2))
    return text

# -------------------------- DES Tables --------------------------

# Initial Permutation Table (IP)
IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]

# Final Permutation Table (IP-1)
IP_INV = [40,8,48,16,56,24,64,32,
          39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30,
          37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28,
          35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26,
          33,1,41,9,49,17,57,25]

# Expansion Table (32-bit to 48-bit)
E = [32,1,2,3,4,5,4,5,6,7,8,9,
     8,9,10,11,12,13,12,13,14,15,16,17,
     16,17,18,19,20,21,20,21,22,23,24,25,
     24,25,26,27,28,29,28,29,30,31,32,1]

# Simplified S-Box (S1 only for demonstration)
S_BOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
]

# Permutation after S-Box
P = [16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
     19,13,30,6,22,11,4,25]

# -------------------------- Key Setup --------------------------

KEY = "MYDESKEY"          # 8-character key = 64-bit
key_bits = string_to_bits(KEY)

# For simplicity, using same 48-bit key for all 16 rounds
round_keys = [key_bits[:48]] * 16

# -------------------------- DES Round Function --------------------------

def des_round(L, R, K):
    # DES round function
    # L: Left 32-bit half
    # R: Right 32-bit half
    # K: 48-bit round key

    # Step 1: Expand R from 32 to 48 bits using E table
    ER = permute(R, E)

    # Step 2: XOR expanded R with round key
    B = xor(ER, K)

    # Step 3: Apply S-Box substitution (simplified here)
    # Normally split into 8 6-bit blocks, apply S1-S8
    # For demonstration, using first 32 bits of B only

    # Step 4: Apply P permutation
    R_new = permute(B[:32], P)

    # Step 5: XOR with left half
    R_new = xor(L, R_new)

    return R_new

# -------------------------- Encrypt / Decrypt Block --------------------------

def des_block(block_bits, keys):
    # Perform initial permutation
    block_bits = permute(block_bits, IP)

    # Split into left and right halves
    L = block_bits[:32]
    R = block_bits[32:]

    # Perform 16 rounds
    for K in keys:
        R_new = des_round(L, R, K)
        L, R = R, R_new  # swap halves

    # Combine halves in reverse order
    combined = R + L

    # Apply final permutation
    return permute(combined, IP_INV)

# -------------------------- Main Program --------------------------

message = "HELLODES"          # 8-character plaintext
message_bits = string_to_bits(message)

# -------------------------- Encryption --------------------------
cipher_bits = des_block(message_bits, round_keys)
cipher_text = bits_to_string(cipher_bits)
print("Encrypted:", cipher_text)

# -------------------------- Decryption --------------------------
# Reverse round keys for decryption
plain_bits = des_block(cipher_bits, round_keys[::-1])
plain_text = bits_to_string(plain_bits)
print("Decrypted:", plain_text)
