import argparse
import logging
import configparser
import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(filename='data_image_conversion.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def encrypt_data(data, key, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        raise

def data_to_image(encrypted_data, output_image, width):
    try:
        if len(encrypted_data) % 3 != 0:
            encrypted_data += b'\0' * (3 - len(encrypted_data) % 3)
        pixel_values = [(encrypted_data[i], encrypted_data[i+1], encrypted_data[i+2]) 
                        for i in range(0, len(encrypted_data), 3)]
        img_height = (len(pixel_values) + width - 1) // width
        image = Image.new('RGB', (width, img_height), color='white')
        image.putdata(pixel_values[:width * img_height])
        image.save(output_image)
        logging.info(f"Image saved to {output_image}")
    except Exception as e:
        logging.error(f"Error during image creation: {e}")
        raise

def decrypt_data(encrypted_data, key, iv):
    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    except Exception as e:
        logging.error(f"Error during decryption: {e}")
        raise

def image_to_data(image_path, key, iv):
    try:
        image = Image.open(image_path)
        pixels = list(image.getdata())
        binary_data = bytearray([val for pixel in pixels for val in pixel])
        binary_data = binary_data.rstrip(b'\0')
        decrypted_data = decrypt_data(binary_data, key, iv)
        return decrypted_data
    except Exception as e:
        logging.error(f"Error during image to data conversion: {e}")
        raise

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Encrypt data and save as image, or decrypt image to recover data.")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('--input', required=True, help="Input file (data for encryption or image for decryption)")
    parser.add_argument('--output', required=True, help="Output file (image for encryption or recovered data for decryption)")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config()
    validate_config(config)
    width = int(config.get('width'))

    try:
        if args.action == 'encrypt':
            if not os.path.isfile(config.get('key_file')) or not os.path.isfile(config.get('iv_file')):
                key = os.urandom(32)
                iv = os.urandom(16)
                with open(config.get('key_file'), 'wb') as kf:
                    kf.write(key)
                with open(config.get('iv_file'), 'wb') as ivf:
                    ivf.write(iv)
                logging.info(f"Generated new key and IV.")
            else:
                with open(config.get('key_file'), 'rb') as kf:
                    key = kf.read()
                with open(config.get('iv_file'), 'rb') as ivf:
                    iv = ivf.read()
                logging.info(f"Loaded existing key and IV.")

            if not os.path.isfile(args.input):
                raise FileNotFoundError(f"Input file {args.input} not found")
            
            with open(args.input, 'rb') as file:
                input_data = file.read()
            
            encrypted_data = encrypt_data(input_data, key, iv)
            data_to_image(encrypted_data, args.output, width)
            logging.info(f"Data encrypted and image saved as {args.output}")
        
        elif args.action == 'decrypt':
            with open(config.get('key_file'), 'rb') as kf:
                key = kf.read()
            with open(config.get('iv_file'), 'rb') as ivf:
                iv = ivf.read()
            
            recovered_data = image_to_data(args.input, key, iv)
            with open(args.output, 'wb') as file:
                file.write(recovered_data)
            logging.info(f"Image decrypted and data saved as {args.output}")

    except Exception as e:
        logging.error(f"Error in main process: {e}")
        raise

if __name__ == "__main__":
    main()
