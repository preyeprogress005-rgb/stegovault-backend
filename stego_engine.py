import base64
import io
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str) -> bytes:
    password_bytes = password.encode()
    salt = b'stego_vault_salt_secure_2026'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))

def encrypt_text(text: str, password: str) -> str:
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_text(cipher_text: str, password: str) -> str:
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(cipher_text.encode()).decode()

def encode_image(image_bytes: bytes, text: str, password: str) -> bytes:
    encrypted_msg = encrypt_text(text, password) + "#####"
    binary_msg = ''.join(format(ord(char), '08b') for char in encrypted_msg)

    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    pixels = img.load()
    width, height = img.size

    data_index = 0
    msg_len = len(binary_msg)

    for y in range(height):
        for x in range(width):
            if data_index >= msg_len:
                break

            r, g, b = pixels[x, y]

            if data_index < msg_len:
                r = (r & ~1) | int(binary_msg[data_index])
                data_index += 1
            if data_index < msg_len:
                g = (g & ~1) | int(binary_msg[data_index])
                data_index += 1
            if data_index < msg_len:
                b = (b & ~1) | int(binary_msg[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

    output = io.BytesIO()
    img.save(output, format="PNG")
    return output.getvalue()

def decode_image(image_bytes: bytes, password: str) -> str:
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    pixels = img.load()
    width, height = img.size

    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ""
    for byte in all_bytes:
        decoded_text += chr(int(byte, 2))
        if decoded_text.endswith("#####"):
            break

    if "#####" not in decoded_text:
        raise ValueError("No hidden message marker found.")

    cipher_text = decoded_text.replace("#####", "")
    return decrypt_text(cipher_text, password)
