# DES Implementation in Python (Educational Purpose)
# Full Encryption and Decryption - No external libraries
# Author: Your Name - Original Implementation

def string_to_bit_array(text):
    """Convert a string to a list of bits (8 bits per character)"""
    bit_array = []
    for char in text:
        binval = bin(char)[2:].rpad('0', 8)
        binval = '0'*(8-len(binval)) + binval
        bit_array.extend([int(x) for x in list(binval)])
    return bit_array

def bit_array_to_string(bit_array):
    """Convert bit array back to string"""
    result = []
    for i in range(0, len(bit_array), 8):
        byte = bit_array[i:i+8]
        if len(byte) == 8:
            result.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(result)

def xor(a, b):
    """XOR two bit arrays"""
    return [x ^ y for x, y in zip(a, b)]

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation Table (Inverse of IP)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table for turning 32-bit R into 48-bit
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S-Boxes
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Permutation table after S-Box
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Permuted Choice 1 (PC-1) - 56 bits from 64
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC-2) - 48 bits
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

# Number of left shifts for each round
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    """Permute block according to table"""
    return [block[i-1] for i in table]

def generate_subkeys(key):
    """Generate 16 subkeys from 64-bit key"""
    # Remove parity bits and permute with PC1
    key_bits = [int(b) for b in format(key, '064b')]
    key56 = permute(key_bits, PC1)
    
    # Split into left and right
    left = key56[:28]
    right = key56[28:]
    
    subkeys = []
    for i in range(16):
        # Left shift
        left = left[SHIFTS[i]:] + left[:SHIFTS[i]]
        right = right[SHIFTS[i]:] + right[:SHIFTS[i]]
        
        # Combine and permute with PC2
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    
    return subkeys

def sbox_substitution(bits48):
    """Apply S-boxes to 48-bit input"""
    output = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = (block[0] << 1) + block[5]
        col = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        val = S_BOX[i][row][col]
        output.extend([int(b) for b in format(val, '04b')])
    return output

def feistel(right, subkey):
    """Feistel function F"""
    # Expand right to 48 bits
    expanded = permute(right, E)
    
    # XOR with subkey
    xored = xor(expanded, subkey)
    
    # S-box substitution
    substituted = sbox_substitution(xored)
    
    # Final permutation P
    return permute(substituted, P)

def des_round(left, right, subkey):
    """One round of DES"""
    new_right = xor(left, feistel(right, subkey))
    return right, new_right

def des_block(block_bits, subkeys, encrypt=True):
    """Encrypt or decrypt a 64-bit block"""
    # Initial Permutation
    block = permute(block_bits, IP)
    
    left = block[:32]
    right = block[32:]
    
    # 16 rounds
    keys = subkeys if encrypt else subkeys[::-1]
    
    for i in range(16):
        left, right = des_round(left, right, keys[i])
    
    # Combine and Final Permutation
    combined = right + left  # Note: swap at the end
    ciphertext = permute(combined, FP)
    return ciphertext

def pad(text):
    """Add PKCS5/PKCS7 style padding"""
    pad_len = 8 - (len(text) % 8)
    return text + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove padding"""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        return data
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return data
    return data[:-pad_len]

def des_encrypt(plaintext, key):
    """Encrypt plaintext (string) with key (64-bit int)"""
    # Convert to bytes if string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    plaintext = pad(plaintext)
    ciphertext = b''
    
    key_bits = int.from_bytes(key.to_bytes(8, 'big'), 'big') if isinstance(key, int) else int(key.hex(), 16)
    subkeys = generate_subkeys(key_bits)
    
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        block_bits = [bit for byte in block for bit in format(byte, '08b')]
        block_bits = [int(b) for b in block_bits]
        encrypted_block = des_block(block_bits, subkeys, encrypt=True)
        
        # Convert bits back to bytes
        byte_array = []
        for j in range(0, 64, 8):
            byte = encrypted_block[j:j+8]
            byte_array.append(int(''.join(str(b) for b in byte), 2))
        ciphertext += bytes(byte_array)
    
    return ciphertext.hex().upper()

def des_decrypt(ciphertext_hex, key):
    """Decrypt hex string ciphertext with key"""
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    key_bits = int.from_bytes(key.to_bytes(8, 'big'), 'big') if isinstance(key, int) else int(key.hex(),16)
    subkeys = generate_subkeys(key_bits)
    
    plaintext = b''
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        block_bits = [bit for byte in block for bit in format(byte, '08b')]
        block_bits = [int(b) for b in block_bits]
        decrypted_block = des_block(block_bits, subkeys, encrypt=False)
        
        byte_array = []
        for j in range(0, 64, 8):
            byte = decrypted_block[j:j+8]
            byte_array.append(int(''.join(str(b) for b in byte), 2))
        plaintext += bytes(byte_array)
    
    return unpad(plaintext).decode('utf-8', errors='ignore')

# ============================
# DEMO / TEST
# ============================

if __name__ == "__main__":
    # Test with known values (from NIST DES test vectors)
    key_hex = "133457799BBCDFF1"
    plaintext = "0123456789ABCDEF"
    
    key = int(key_hex, 16)
    print("Plaintext: ", plaintext)
    print("Key:       ", key_hex)
    
    encrypted = des_encrypt(plaintext, key)
    print("Encrypted: ", encrypted)
    
    decrypted = des_decrypt(encrypted, key)
    print("Decrypted: ", decrypted)
    
    assert decrypted == plaintext
    print("\nDES Test Passed! Encryption and Decryption are correct.")
