import argparse

def parse_args():
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
            else:
                with open(config.get('key_file'), 'rb') as kf:
                    key = kf.read()
                with open(config.get('iv_file'), 'rb') as ivf:
                    iv = ivf.read()

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
