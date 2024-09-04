import argparse
import logging
import configparser
import os
from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
log_file_path = os.path.join(log_dir, 'data_image_conversion.log')
logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file='config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file)
    if 'settings' not in config:
        raise ValueError("Config file is missing 'settings' section.")
    return config['settings']

def validate_config(config):
    required_fields = ['input_file', 'output_image', 'key_file', 'iv_file', 'width']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required configuration field: {field}")
    if not config['width'].isdigit() or int(config['width']) <= 0:
        raise ValueError("Width must be a positive integer.")

def read_key_iv(key_file, iv_file):
    try:
        with open(key_file, 'rb') as kf:
            key = kf.read()
        with open(iv_file, 'rb') as ivf:
            iv = ivf.read()

        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes long, but got {len(key)} bytes.")
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes long, but got {len(iv)} bytes.")

        logging.info(f"Key length: {len(key)} bytes")
        logging.info(f"IV length: {len(iv)} bytes")
        logging.debug(f"Key (hex): {key.hex()}")
        logging.debug(f"IV (hex): {iv.hex()}")
        return key, iv
    except Exception as e:
        logging.error(f"Error reading key or IV: {e}")
        raise

def pad_data(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(data, block_size=16):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_length]

def encrypt_data_in_chunks(input_file, key, iv, chunk_size=64*1024):
    encrypted_data = bytearray()
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(input_file, 'rb') as file:
            while chunk := file.read(chunk_size):
                padded_chunk = pad_data(chunk)
                encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                encrypted_data.extend(encrypted_chunk)
                encryptor = cipher.encryptor()  # Reset encryptor for next chunk

        logging.info(f"Data encrypted. Total length: {len(encrypted_data)} bytes.")
        return encrypted_data
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        raise

def decrypt_data_in_chunks(encrypted_file, key, iv, chunk_size=64*1024):
    decrypted_data = bytearray()
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        with open(encrypted_file, 'rb') as file:
            while chunk := file.read(chunk_size):
                decrypted_chunk = decryptor.update(chunk)
                decrypted_data.extend(decrypted_chunk)

        decrypted_data += decryptor.finalize()  # Ensure finalization of decryption
        decrypted_data = unpad_data(decrypted_data)
        logging.info(f"Data decrypted. Total length: {len(decrypted_data)} bytes.")
        return decrypted_data
    except Exception as e:
        logging.error(f"Error during decryption: {e}")
        raise

def data_to_image(encrypted_data, output_image, width):
    try:
        img_height = (len(encrypted_data) + width * 3 - 1) // (width * 3)
        image = Image.new('RGB', (width, img_height), color='white')

        pixel_data = []
        for i in range(0, len(encrypted_data), 3):
            pixel = encrypted_data[i:i+3]
            if len(pixel) < 3:
                pixel += bytes(3 - len(pixel))  # Add padding to fit the RGB format
            pixel_data.append(tuple(pixel))

        image.putdata(pixel_data)
        image.save(output_image, format='BMP')
        logging.info(f"Image saved to {output_image} with size ({width}, {img_height})")
        logging.info(f"Image can hold up to {width * img_height * 3} bytes.")
    except Exception as e:
        logging.error(f"Error during image creation: {e}")
        raise

def image_to_data(image_path, key, iv):
    try:
        with Image.open(image_path) as image:
            if image.format != 'BMP':
                raise ValueError(f"Image file {image_path} is not in BMP format. Current format: {image.format}")

            pixels = list(image.getdata())
            binary_data = bytearray()
            for pixel in pixels:
                binary_data.extend(pixel)

            # Remove potential padding bytes (zero bytes) and check length
            binary_data = binary_data.rstrip(b'\x00')
            logging.info(f"Extracted binary data length after stripping zeros: {len(binary_data)}")

            # Verify that the length is a multiple of the block size (16 bytes)
            if len(binary_data) % 16 != 0:
                raise ValueError(f"Extracted binary data length is not a multiple of the block size (16 bytes). Length: {len(binary_data)}")

            # Decrypt the data
            decrypted_data = decrypt_data_in_chunks(encrypted_file=image_path, key=key, iv=iv)
            return decrypted_data
    except UnidentifiedImageError as e:
        logging.error(f"Unable to identify image file {image_path}: {e}")
        raise
    except ValueError as e:
        logging.error(f"Value error during image to data conversion: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during image to data conversion: {e}")
        raise

def validate_file_path(path, mode='r'):
    """ Check if the file exists and is accessible. """
    if mode == 'r':
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Input file {path} does not exist or is not a file.")
    elif mode == 'w':
        # For output files, just check if the directory is writable
        directory = os.path.dirname(path)
        if directory and not os.access(directory, os.W_OK):
            raise PermissionError(f"Cannot write to the directory {directory}.")
    else:
        raise ValueError(f"Invalid mode {mode}. Expected 'r' or 'w'.")

def main():
    parser = argparse.ArgumentParser(description='Encrypt and decrypt data using images.')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform: encrypt or decrypt')
    parser.add_argument('--input', required=True, help='Input file (data for encryption or image for decryption)')
    parser.add_argument('--output', required=True, help='Output file (image for encryption or data file for decryption)')
    args = parser.parse_args()

    try:
        # Validate action
        if args.action not in ['encrypt', 'decrypt']:
            raise ValueError(f"Invalid action: {args.action}. Must be 'encrypt' or 'decrypt'.")

        # Load and validate configuration
        config = load_config()
        validate_config(config)

        # Validate input and output file paths
        if args.action == 'encrypt':
            validate_file_path(args.input, mode='r')
            validate_file_path(args.output, mode='w')
        elif args.action == 'decrypt':
            validate_file_path(args.input, mode='r')
            validate_file_path(args.output, mode='w')

        key_file = config.get('key_file')
        iv_file = config.get('iv_file')
        width = int(config.get('width'))

        key, iv = read_key_iv(key_file, iv_file)

        if args.action == 'encrypt':
            encrypted_data = encrypt_data_in_chunks(args.input, key, iv)
            data_to_image(encrypted_data, args.output, width)
            logging.info(f"Data encrypted and image saved as {args.output}")

        elif args.action == 'decrypt':
            recovered_data = image_to_data(args.input, key, iv)

            if recovered_data is not None:
                with open(args.output, 'wb') as file:
                    file.write(recovered_data)
                logging.info(f"Image decrypted and data saved as {args.output}")
            else:
                logging.error("Decryption failed. No data recovered from the image.")

    except (ValueError, FileNotFoundError, PermissionError) as e:
        logging.error(f"Validation error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
