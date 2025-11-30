
# PLAYFAIR CIPHER IMPLEMENTATION
# Encryption & Decryption

#create 5x5 Playfair matrix from key
def create_matrix(key):
    key = key.upper().replace(" ", "")
    matrix = []
    used = set()
    #J merged with I
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 

    # Add key letters (no duplicates)
    for c in key:
        if c == "J": 
            c = "I"
        if c not in used:
            used.add(c)
            matrix.append(c)

    # Add remaining letters
    for c in alphabet:
        if c not in used:
            used.add(c)
            matrix.append(c)

    # Convert list to 5x5 matrix
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def prepare_text(text):
    text = text.upper().replace(" ", "").replace("J", "I")
    prepared = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i+1 < len(text):
            b = text[i+1]
            if a == b:
                prepared += a + "X"
                i += 1
            else:
                prepared += a + b
                i += 2
        else:
            prepared += a + "X"
            i += 1
    return prepared


#Function to find row/column of a letter in matrix
def find_position(matrix, letter):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == letter:
                return r, c
    #Letter not found
    return None  

#error handling
def playfair_encrypt(text, matrix):
    text = prepare_text(text)
    encrypted = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        pos1 = find_position(matrix, a)
        pos2 = find_position(matrix, b)

        # Error handling: if letter not in matrix
        if pos1 is None or pos2 is None:
            missing = []
            if pos1 is None: missing.append(a)
            if pos2 is None: missing.append(b)
            print(f"Error: Letter(s) {', '.join(missing)} not in matrix!")
            return None

        r1, c1 = pos1
        r2, c2 = pos2

        if r1 == r2:  # Same row → shift right
            encrypted += matrix[r1][(c1+1)%5]
            encrypted += matrix[r2][(c2+1)%5]
        elif c1 == c2:  # Same column → shift down
            encrypted += matrix[(r1+1)%5][c1]
            encrypted += matrix[(r2+1)%5][c2]
        else:  # Rectangle → swap columns
            encrypted += matrix[r1][c2]
            encrypted += matrix[r2][c1]

    return encrypted

# Decrypt text using Playfair Cipher with error handling
def playfair_decrypt(cipher, matrix):
    decrypted = ""

    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i+1]
        pos1 = find_position(matrix, a)
        pos2 = find_position(matrix, b)

        # Error handling: if letter not in matrix
        if pos1 is None or pos2 is None:
            missing = []
            if pos1 is None: missing.append(a)
            if pos2 is None: missing.append(b)
            print(f"Error: Letter(s) {', '.join(missing)} not in matrix!")
            return None

        r1, c1 = pos1
        r2, c2 = pos2

        if r1 == r2:  # Same row → shift left
            decrypted += matrix[r1][(c1-1)%5]
            decrypted += matrix[r2][(c2-1)%5]
        elif c1 == c2:  # Same column → shift up
            decrypted += matrix[(r1-1)%5][c1]
            decrypted += matrix[(r2-1)%5][c2]
        else:  # Rectangle → swap columns
            decrypted += matrix[r1][c2]
            decrypted += matrix[r2][c1]

    return decrypted

#Input
KEY = "SHAIKAT"
PLAINTEXT = "CRYPTOGRAPHY"

#Create Playfair Matrix
matrix = create_matrix(KEY)
print("Playfair 5x5 Matrix:")
for row in matrix:
    print(row)

#Encryption
ciphertext = playfair_encrypt(PLAINTEXT, matrix)
if ciphertext:
    print("\nEncryption:")
    print("Plaintext:", PLAINTEXT)
    print("Ciphertext:", ciphertext)
else:
    print("Encryption failed due to invalid letters.")

#Decryption
if ciphertext:
    decrypted_text = playfair_decrypt(ciphertext, matrix)
    if decrypted_text:
        print("\nDecryption:")
        print("Ciphertext:", ciphertext)
        print("Decrypted text:", decrypted_text)
    else:
        print("Decryption failed due to invalid letters.")

