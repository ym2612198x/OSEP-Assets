import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


parser = argparse.ArgumentParser(description="AES-256 encryption and decryption")
parser.add_argument("-i", "--input", required=True, help="Input file path (for plaintext)")
parser.add_argument("-o", "--output", required=True, help="Output file path (for encrypted data)")
parser.add_argument("-m", "--method", required=True, help="Encryption method (aes/caesar)")

args = parser.parse_args()


def caesar_encrypt(input_file, output_file):

    with open(input_file, "rb") as input_file:
        data = input_file.read()
    
    # unencrypted
    print(f"Unencrypted size: {len(data)} bytes")
    hex_unencrypted = ', '.join(f"0x{byte:02X}" for byte in data)
    #print(f"Unencrypted data (hex):\n{hex_unencrypted}")
    print("")

    shift = 5
    encrypted_bytes = bytearray()
    for byte in data:
        shifted_byte = (byte + shift) % 256
        encrypted_bytes.append(shifted_byte)

    # encrypted
    print(f"Encrypted size: {len(data)} bytes")
    hex_encrypted = ', '.join(f"0x{byte:02X}" for byte in encrypted_bytes)
    print(f"Encrypted data (hex):\n{hex_encrypted}")
    print("")

    with open(output_file, "wb") as out_file:
        out_file.write(encrypted_bytes)

    # decrypted
    decrypted_bytes = bytearray()
    for byte in encrypted_bytes:
        shifted_byte = (byte - shift) % 256
        decrypted_bytes.append(shifted_byte)
    print(f"Decrypted size: {len(data)} bytes")
    hex_decrypted = ', '.join(f"0x{byte:02X}" for byte in decrypted_bytes)
    #print(f"Decrypted data (hex): {hex_decrypted}")
    

def aes_encrypt(input_file, output_file):

    key = bytes([
        0x66, 0x7E, 0x40, 0xAB, 0x25, 0x57, 0x2A, 0xE2, 0x0C, 0x2D, 0x85, 0x49, 0x44, 0x39, 0xBC, 0x96,
        0x7C, 0x47, 0xB6, 0xF2, 0xE6, 0xF6, 0xA8, 0x4E, 0x4C, 0x5E, 0x30, 0x56, 0xB6, 0x60, 0x74, 0x78
    ])

    iv = bytes([
        0xF6, 0x65, 0x65, 0xC7, 0x63, 0xC9, 0x2E, 0xAE, 0x09, 0xE7, 0x3E, 0x6A, 0xF6, 0x94, 0x54, 0xE0
    ])

    with open(input_file, "rb") as input_file:
        data = input_file.read()

    print(f"Unencrypted size: {len(data)} bytes")
    hex_unencrypted = ', '.join(f"0x{byte:02X}" for byte in data)
    #print(f"Unencrypted data (hex):\n{hex_unencrypted}")
    print("")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    hex_ciphertext = ', '.join(f"0x{byte:02X}" for byte in ciphertext)
    print(f"Encrypted size: {len(ciphertext)} bytes")
    print(f"Encrypted data (hex):\n{hex_ciphertext}")
    print("")

    with open(output_file, "wb") as out_file:
        out_file.write(ciphertext)

    decipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(decipher.decrypt(ciphertext), AES.block_size)
    hex_decrypted_data = ', '.join(f"0x{byte:02X}" for byte in decrypted_data)
    print(f"Decrypted size: {len(decrypted_data)} bytes")
    #print(f"Decrypted data (hex):\n{hex_decrypted_data}")
    print("")

    print(f"Encrypted data saved to {output_file}")
    print("")

if args.method == "aes":
    aes_encrypt(args.input, args.output)

if args.method == "caesar":
    caesar_encrypt(args.input, args.output)
