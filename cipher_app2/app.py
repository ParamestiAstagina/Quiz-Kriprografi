import os
import numpy as np
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Vigenere Cipher helper functions
def vigenere_encrypt(plain_text, key):
    key = key.upper()
    plain_text = plain_text.upper()
    cipher_text = ''
    
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plain_text_as_int = [ord(i) for i in plain_text]
    
    for i in range(len(plain_text_as_int)):
        if plain_text[i].isalpha():  # Pastikan hanya huruf yang diproses
            value = (plain_text_as_int[i] + key_as_int[i % key_length]) % 26
            cipher_text += chr(value + 65)  
        else:
            cipher_text += plain_text[i]  # Jika bukan huruf, tidak dienkripsi

    return cipher_text

def vigenere_decrypt(cipher_text, key):
    key = key.upper()
    cipher_text = cipher_text.upper()
    plain_text = ''
    
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    cipher_text_as_int = [ord(i) for i in cipher_text]
    
    for i in range(len(cipher_text_as_int)):
        if cipher_text[i].isalpha():  # Pastikan hanya huruf yang diproses
            value = (cipher_text_as_int[i] - key_as_int[i % key_length]) % 26
            plain_text += chr(value + 65)  
        else:
            plain_text += cipher_text[i]  # Jika bukan huruf, tidak didekripsi

    return plain_text

# Playfair Cipher helper functions
def generate_playfair_table(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()

    for char in key:
        if char not in used and char.isalpha():
            matrix.append(char)
            used.add(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 
    for char in alphabet:
        if char not in used:
            matrix.append(char)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    raise ValueError(f"Character {char} not found in Playfair matrix.")

def playfair_encrypt(plain_text, key):
    matrix = generate_playfair_table(key)
    plain_text = plain_text.upper().replace('J', 'I')

    # Prepare pairs
    pairs = []
    i = 0
    while i < len(plain_text):
        if i == len(plain_text) - 1:
            pairs.append((plain_text[i], 'X'))
            i += 1
        elif plain_text[i] == plain_text[i + 1]:
            pairs.append((plain_text[i], 'X'))
            i += 1
        else:
            pairs.append((plain_text[i], plain_text[i + 1]))
            i += 2

    # Encrypt pairs
    cipher_text = ""
    for char1, char2 in pairs:
        try:
            row1, col1 = playfair_find_position(matrix, char1)
            row2, col2 = playfair_find_position(matrix, char2)
        except ValueError as e:
            print(e)
            return "Character not found in Playfair matrix"

        if row1 == row2:
            cipher_text += matrix[row1][(col1 + 1) % 5]
            cipher_text += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            cipher_text += matrix[(row1 + 1) % 5][col1]
            cipher_text += matrix[(row2 + 1) % 5][col2]
        else:
            cipher_text += matrix[row1][col2]
            cipher_text += matrix[row2][col1]

    return cipher_text

def playfair_decrypt(cipher_text, key):
    matrix = generate_playfair_table(key)
    cipher_text = cipher_text.upper().replace('J', 'I')

    pairs = [(cipher_text[i], cipher_text[i + 1]) for i in range(0, len(cipher_text), 2)]

    plain_text = ""
    for char1, char2 in pairs:
        try:
            row1, col1 = playfair_find_position(matrix, char1)
            row2, col2 = playfair_find_position(matrix, char2)
        except ValueError as e:
            print(e)
            return "Character not found in Playfair matrix"

        if row1 == row2:
            plain_text += matrix[row1][(col1 - 1) % 5]
            plain_text += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plain_text += matrix[(row1 - 1) % 5][col1]
            plain_text += matrix[(row2 - 1) % 5][col2]
        else:
            plain_text += matrix[row1][col2]
            plain_text += matrix[row2][col1]

    return plain_text

# Hill Cipher helper functions
import numpy as np

def hill_encrypt(plain_text, key_matrix):
    key_matrix = np.array(key_matrix)
    plain_text = plain_text.upper().replace(" ", "")
    block_size = key_matrix.shape[0]

    if len(plain_text) % block_size != 0:
        plain_text += 'X' * (block_size - len(plain_text) % block_size)

    blocks = [plain_text[i:i + block_size] for i in range(0, len(plain_text), block_size)]

    cipher_text = ''
    for block in blocks:
        block_vector = np.array([ord(char) - ord('A') for char in block])
        encrypted_vector = np.dot(key_matrix, block_vector) % 26
        cipher_text += ''.join(chr(int(num) + ord('A')) for num in encrypted_vector)

    return cipher_text

def mod_inv(a, mod):
    """Menghitung invers dari a dalam modulo mod"""
    for i in range(1, mod):
        if (a * i) % mod == 1:
            return i
    raise ValueError(f"Tidak ada invers untuk {a} dalam mod {mod}")

def hill_decrypt(cipher_text, key_matrix):
    key_matrix = np.array(key_matrix)
    cipher_text = cipher_text.upper().replace(" ", "")
    block_size = key_matrix.shape[0]

    determinant = int(np.round(np.linalg.det(key_matrix))) % 26
    if determinant == 0:
        raise ValueError("Determinant is 0, matriks kunci tidak bisa di-invers-kan.")

    try:
        determinant_inv = mod_inv(determinant, 26) 
    except ValueError as e:
        return str(e)

    adjugate_matrix = np.round(determinant * np.linalg.inv(key_matrix)).astype(int) % 26

    key_matrix_inv = (determinant_inv * adjugate_matrix) % 26

    blocks = [cipher_text[i:i + block_size] for i in range(0, len(cipher_text), block_size)]

    plain_text = ''
    for block in blocks:
        block_vector = np.array([ord(char) - ord('A') for char in block])
        decrypted_vector = np.dot(key_matrix_inv, block_vector) % 26
        plain_text += ''.join(chr(int(num) + ord('A')) for num in decrypted_vector)

    return plain_text


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if request.form.get('clear'):
            return redirect(url_for('index'))

        if 'file_input' in request.files and request.files['file_input'].filename != '':
            file = request.files['file_input']
            if file and allowed_file(file.filename):
                message = file.read().decode('utf-8')  
            else:
                flash('Invalid file type. Only .txt files are allowed!', 'error')
                return redirect(url_for('index'))
        else:
            message = request.form['message']
        
        key = request.form['key']
        cipher_type = request.form['cipher_type']
        operation = request.form['operation']

        if len(key) < 12 and cipher_type != 'hill':
            flash('Key must be at least 12 characters long!', 'error')
            return redirect(url_for('index'))

        result = None
        # Vigenere Cipher
        if cipher_type == 'vigenere':
            if operation == 'encrypt':
                result = vigenere_encrypt(message, key)
            else:
                result = vigenere_decrypt(message, key)

        # Playfair Cipher
        elif cipher_type == 'playfair':
            if operation == 'encrypt':
                result = playfair_encrypt(message, key)
            else:
                result = playfair_decrypt(message, key)

        # Hill Cipher
        elif cipher_type == 'hill':
            hill_key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # Example 3x3 key matrix
            if operation == 'encrypt':
                result = hill_encrypt(message, hill_key)
            else:
                result = hill_decrypt(message, hill_key)

        return render_template('index.html', result=result, message=message, key=key, cipher_type=cipher_type, operation=operation)

    return render_template('index.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)