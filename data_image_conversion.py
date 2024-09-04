import argparse
import logging
import configparser
import os
from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(filename='data_image_conversion.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables to store encrypted data and its original length
encrypted_data = bytearray() 
original_data_len = 0

def load_config(config_file='config.ini'):
    """Load configuration from a file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    if 'settings' not in config:
        raise ValueError("Config file is missing 'settings' section.")
    return config['settings']

def validate_config(config):
    """Validate configuration settings."""
    required_fields = ['input_file', 'output_image', 'key_file', 'iv_file', 'width']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required configuration field: {field}")
    if not config['width'].isdigit() or int(config['width']) <= 0:
        raise ValueError("Width must be a positive integer.")

def read_key_iv(key_file, iv_file):
    """Read key and IV from files."""
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
        return key, iv
    except Exception as e:
        logging.error(f"Error reading key or IV: {e}")
        raise

def pad_data(data, block_size=16):
    """Pads data using PKCS#7 padding to the specified block size."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    padded_data = data + padding
    return padded_data

def unpad_data(data, block_size=16):
    """Removes PKCS#7 padding from data."""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_length]

def encrypt_data(data, key, iv):
    """Encrypt the data using AES encryption."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data
        padded_data = pad_data(data, block_size=16)  

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        logging.info(f"Data length before padding: {len(data)}")
        logging.info(f"Data length after padding: {len(padded_data)}")
        logging.info(f"Data encrypted. Length: {len(encrypted_data)}")
        logging.debug(f"Encrypted data (hex): {encrypted_data.hex()}")  # Log hex output
        return encrypted_data
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        raise

def data_to_image(data, output_image, width):
    """Convert encrypted data to an image."""
    global encrypted_data  # Declare encrypted_data as global
    global original_data_len # Declare original_data_len as global

    try:
        encrypted_data = data  # Store the data in the global variable
        original_data_len = len(encrypted_data)  # Store the original length before padding

        # Calculate padding length
        padding_length = 16 - (len(encrypted_data) % 16) if len(encrypted_data) % 16 != 0 else 0
        # Explicitly add padding bytes as pixel values
        encrypted_data += bytes([padding_length] * padding_length)

        # Calculate image height
        img_height = (len(encrypted_data) + width * 3 - 1) // (width * 3)

        # Create the image
        image = Image.new('RGB', (width, img_height), color='white')
        pixel_data = []
        for i in range(0, len(encrypted_data), 3):
            if i + 2 < len(encrypted_data):
                pixel_data.append((encrypted_data[i], encrypted_data[i + 1], encrypted_data[i + 2]))
            else:
                # Handle padding at the end 
                remaining_bytes = len(encrypted_data) - i
                if remaining_bytes == 1:
                    pixel_data.append((encrypted_data[i], 0, 0))
                elif remaining_bytes == 2:
                    pixel_data.append((encrypted_data[i], encrypted_data[i+1], 0))

        image.putdata(pixel_data)
        image.save(output_image, format='BMP')
        logging.info(f"Image saved to {output_image}")
    except Exception as e:
        logging.error(f"Error during image creation: {e}")
        raise

def decrypt_data(encrypted_data, key, iv):
    """Decrypt the encrypted data using AES decryption."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the data
        decrypted_data = unpad_data(decrypted_padded_data, block_size=16)

        logging.info(f"Decrypted padded data length: {len(decrypted_padded_data)}")
        logging.info(f"Data decrypted. Length: {len(decrypted_data)}")
        return decrypted_data
    except ValueError as e:
        logging.error(f"Padding error during decryption: {e}. Decrypted padded data: {decrypted_padded_data}")
        raise
    except Exception as e:
        logging.error(f"Error during decryption: {e}")
        raise

def image_to_data(image_path, key, iv):
    """Convert an image back to data."""
    global encrypted_data  # Access the global encrypted_data
    global original_data_len # Access the global original_data_len

    try:
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image file {image_path} does not exist.")

        logging.info(f"Attempting to open image file: {image_path}")
        with Image.open(image_path) as image:
            if image.format != 'BMP':
                raise ValueError(f"Image file {image_path} is not a BMP image.")

            pixels = list(image.getdata())

            # Extract bytes, stopping at the original data length
            binary_data = bytearray()
            byte_count = 0
            for pixel in pixels:
                for component in pixel:
                    if byte_count < original_data_len:  # Only extract up to the original length
                        binary_data.append(component)
                        byte_count += 1
                    else:
                        break

            # Remove padding (now that we've extracted the correct amount of data)
            padding_length = binary_data[-1] 
            if 1 <= padding_length <= 16:
                binary_data = binary_data[:-padding_length]
            else:
                logging.warning("Invalid padding value found. Possible data corruption.")

            logging.info(f"Extracted binary data length: {len(binary_data)}")
            logging.debug(f"Extracted binary data (hex): {binary_data.hex()}") 
            decrypted_data = decrypt_data(binary_data, key, iv)
            return decrypted_data

    except UnidentifiedImageError as e:
        logging.error(f"Cannot identify image file {image_path}: {e}")
        raise
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise
    except ValueError as e:
        logging.error(f"Invalid image format: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during image to data conversion: {e}")
        raise

def main():
    """Main function to handle command-line arguments and process the data."""
    global encrypted_data # Declare encrypted_data as global

    parser = argparse.ArgumentParser(description='Encrypt and decrypt data using images.')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform: encrypt or decrypt')
    parser.add_argument('--input', required=True, help='Input file (data for encryption or image for decryption)')
    parser.add_argument('--output', required=True, help='Output file (image for encryption or data file for decryption)')
    args = parser.parse_args()

    config = load_config()
    validate_config(config)

    key_file = config.get('key_file')
    iv_file = config.get('iv_file')
    width = int(config.get('width'))

    try:
        key, iv = read_key_iv(key_file, iv_file)  # Ensure correct key and IV are read

        if args.action == 'encrypt':
            if not os.path.isfile(args.input):
                raise FileNotFoundError(f"Input file {args.input} not found")

            with open(args.input, 'rb') as file:
                input_data = file.read()

            logging.info(f"Data length before encryption: {len(input_data)}")
            encrypted_data = encrypt_data(input_data, key, iv)
            data_to_image(encrypted_data, args.output, width)
            logging.info(f"Data encrypted and image saved as {args.output}")

        elif args.action == 'decrypt':
            if not os.path.isfile(args.input):
                raise FileNotFoundError(f"Input file {args.input} not found")

            logging.info(f"Attempting to open image file: {args.input}")
            recovered_data = image_to_data(args.input, key, iv)
            with open(args.output, 'wb') as file:
                file.write(recovered_data)
            logging.info(f"Image decrypted and data saved as {args.output}")

    except Exception as e:
        logging.error(f"Error in main process: {e}")
        raise

if __name__ == "__main__":
    main()