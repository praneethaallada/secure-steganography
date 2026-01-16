import os
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# --- Layer 1: AES-256 Cryptography Logic ---
# NOTE: For production, use a unique salt per secret and store it (or derive differently).
SALT = b'\x28\xbf\x91\xd1\xe6\x19\xda\x04'  # 8-byte static salt (demo only)

def derive_key(password: str) -> bytes:
    """Derive a 32-byte (256-bit) key from password (returns bytes)."""
    # PBKDF2 expects bytes for the password input
    pwd_bytes = password.encode('utf-8')
    # count kept high for security; reduce for local tests if it is too slow
    return PBKDF2(pwd_bytes, SALT, dkLen=32, count=1_000_000, hmac_hash_module=SHA256)

def encrypt_message(plaintext: str, password: str) -> tuple[bytes, bytes]:
    """
    Encrypt the plaintext and return (iv, ciphertext).
    Returning iv first reduces confusion when concatenating.
    """
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC)  # cipher.iv is auto-generated
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return cipher.iv, ciphertext

def decrypt_message(ciphertext: bytes, iv: bytes, password: str) -> str:
    """Decrypt ciphertext using AES-256-CBC with given iv and password."""
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    try:
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except ValueError:
        # Wrong key / corrupted data -> bubble up a clear error
        raise ValueError("Invalid Key/Corrupted Message: Access Denied.")


# --- Layer 2: Simple LSB Steganography (lossless PNG recommended) ---

def _bits_from_bytes(data: bytes):
    """Generator yielding integer bits (0 or 1) from bytes, MSB first."""
    for b in data:
        bits = format(b, '08b')
        for ch in bits:
            yield 1 if ch == '1' else 0

def encode_image(image_path: str, message: str, password: str, output_path: str) -> str:
    """
    Encrypt message and hide length(8 bytes) + IV(16 bytes) + ciphertext inside image LSBs.
    Returns path to saved stego image.
    """
    iv, ciphertext = encrypt_message(message, password)
    hidden_data = iv + ciphertext

    img = Image.open(image_path).convert('RGB')
    width, height = img.size

    # Prepend 8-byte length (big-endian) — length of IV + ciphertext
    length_bytes = len(hidden_data).to_bytes(8, 'big')
    full_data = length_bytes + hidden_data
    total_bits = len(full_data) * 8

    if total_bits > width * height * 3:
        raise ValueError("Image too small to hide the message.")

    # Create a bit generator
    bit_gen = _bits_from_bytes(full_data)

    pixels = img.load()
    bit_count = 0
    for y in range(height):
        for x in range(width):
            if bit_count >= total_bits:
                break
            r, g, b = pixels[x, y]
            new_rgb = []
            for channel in (r, g, b):
                if bit_count < total_bits:
                    try:
                        bit = next(bit_gen)
                    except StopIteration:
                        bit = 0
                    channel = (channel & 0xFE) | bit
                    bit_count += 1
                new_rgb.append(channel)
            pixels[x, y] = tuple(new_rgb)
        if bit_count >= total_bits:
            break

    # Save as PNG (lossless)
    img.save(output_path, 'PNG')
    return output_path


def decode_image(image_path: str, password: str) -> str:
    """
    Extract hidden data from image: read 8-byte length, then that many bytes of hidden data.
    Hidden data format: IV (16 bytes) + ciphertext.
    """
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    pixels = img.load()

    # Function to read N bits (returns list of ints 0/1)
    def read_n_bits(n):
        bits = []
        count = 0
        for y in range(height):
            for x in range(width):
                for channel in pixels[x, y]:
                    if count >= n:
                        return bits
                    bits.append(channel & 1)
                    count += 1
        return bits

    # Step 1: read first 64 bits -> length
    length_bits = read_n_bits(64)
    if len(length_bits) < 64:
        raise ValueError("Image does not contain length header or is corrupted.")
    length_int = int(''.join(map(str, length_bits)), 2)

    # Step 2: read the next length_int * 8 bits (we must skip first 64 bits)
    # We'll iterate through pixels again but skip first 64 LSBs
    bits_needed = length_int * 8
    hidden_bits = []
    seen = 0  # number of LSBs processed (including the initial 64)
    for y in range(height):
        for x in range(width):
            for channel in pixels[x, y]:
                if seen >= 64 and len(hidden_bits) < bits_needed:
                    hidden_bits.append(channel & 1)
                seen += 1
                if len(hidden_bits) >= bits_needed:
                    break
            if len(hidden_bits) >= bits_needed:
                break
        if len(hidden_bits) >= bits_needed:
            break

    if len(hidden_bits) < bits_needed:
        raise ValueError("Image does not contain the full hidden payload.")

    # Convert bits to bytes
    hidden_bytes = bytearray()
    for i in range(0, len(hidden_bits), 8):
        byte_str = ''.join(str(b) for b in hidden_bits[i:i+8])
        hidden_bytes.append(int(byte_str, 2))

    if len(hidden_bytes) < 16:
        raise ValueError("Hidden payload too short to contain IV + ciphertext.")

    iv = bytes(hidden_bytes[:16])
    ciphertext = bytes(hidden_bytes[16:])

    # Decrypt and return plaintext (raises ValueError for wrong password)
    return decrypt_message(ciphertext, iv, password)


# Example usage:
if __name__ == '__main__':
    original_image = "cover_image.png"   # must exist and be big enough
    output_stego_image = "stego_output.png"
    secret_message = "This is the secret battle plan, mission code Project Kavach."
    correct_password = "SecurePassword123"
    wrong_password = "IncorrectPassword"

    print("--- ENCODING PHASE ---")
    try:
        final_image = encode_image(original_image, secret_message, correct_password, output_stego_image)
        print(f"Message encrypted & hidden successfully: {final_image}")
    except Exception as e:
        print("ERROR during encoding:", e)
        raise

    print("\n--- DECODING PHASE (correct password) ---")
    try:
        recovered = decode_image(output_stego_image, correct_password)
        print("Recovered message:", recovered)
    except Exception as e:
        print("ERROR during decoding with correct password:", e)

    print("\n--- DECODING PHASE (wrong password) ---")
    try:
        recovered_wrong = decode_image(output_stego_image, wrong_password)
        print("ERROR: Decryption should have failed but returned:", recovered_wrong)
    except Exception as e:
        print("Expected failure for wrong password:", e)
