
# PLAYFAIR CIPHER IMPLEMENTATION
# Encryption & Decryption

# Step 1: Function to generate the 5x5 Playfair Key Matrix
def generate_key_matrix(key):
    key = key.replace(" ", "").upper()        # Remove spaces & convert to uppercase
    matrix = []                                # This list will store 25 letters
    used = set()                               # To track already added letters

    # Playfair rule: I and J are considered SAME
    key = key.replace("J", "I")

    # Add key letters first
    for ch in key:
        if ch not in used and ch.isalpha():
            used.add(ch)
            matrix.append(ch)

    # Add remaining letters A–Z (except J)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            used.add(ch)
            matrix.append(ch)

    # Convert list into 5x5 matrix
    key_matrix = [matrix[i:i+5] for i in range(5)]
    return key_matrix


# Step 2: Function to format plaintext into digraphs
def format_plaintext(text):
    text = text.replace(" ", "").upper()
    text = text.replace("J", "I")

    formatted = ""
    i = 0

    while i < len(text):
        a = text[i]
        if i+1 < len(text):
            b = text[i+1]
            if a == b:            # Same letters cannot stay together → insert X
                formatted += a + "X"
                i += 1
            else:
                formatted += a + b
                i += 2
        else:
            formatted += a + "X"  # Last odd letter → add X
            i += 1

    return formatted


# Step 3: Find row & column position of a letter in matrix
def find_position(matrix, letter):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == letter:
                return r, c
    return None


# Step 4: Encrypt a pair of letters
def encrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Case 1: Same row → shift right
    if r1 == r2:
        return matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]

    # Case 2: Same column → shift down
    elif c1 == c2:
        return matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]

    # Case 3: Rectangle → swap columns
    else:
        return matrix[r1][c2] + matrix[r2][c1]


# Step 5: Decrypt a pair of letters
def decrypt_pair(a, b, matrix):
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Case 1: Same row → shift left
    if r1 == r2:
        return matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]

    # Case 2: Same column → shift up
    elif c1 == c2:
        return matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]

    # Case 3: Rectangle → swap columns
    else:
        return matrix[r1][c2] + matrix[r2][c1]


# Step 6: Complete encryption function
def encrypt(plaintext, key):
    matrix = generate_key_matrix(key)
    plaintext = format_plaintext(plaintext)
    ciphertext = ""

    for i in range(0, len(plaintext), 2):
        ciphertext += encrypt_pair(plaintext[i], plaintext[i+1], matrix)

    return ciphertext


# Step 7: Complete decryption function
def decrypt(ciphertext, key):
    matrix = generate_key_matrix(key)
    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        plaintext += decrypt_pair(ciphertext[i], ciphertext[i+1], matrix)

    return plaintext


# -------------------------------
# MAIN PROGRAM
# -------------------------------
print("=== PLAYFAIR CIPHER ===")
key = input("Enter Key: ")
text = input("Enter Text: ")

print("\n1. Encrypt")
print("2. Decrypt")

choice = input("Choose option (1/2): ")

if choice == "1":
    encrypted = encrypt(text, key)
    print("\nEncrypted Text:", encrypted)

elif choice == "2":
    decrypted = decrypt(text, key)
    print("\nDecrypted Text:", decrypted)

else:
    print("Invalid Choice!")
