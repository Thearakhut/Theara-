import os
import rsa

def generate_keys():
    """Generate and save RSA keys."""
    os.makedirs('keys', exist_ok=True)
    (pubKey, privKey) = rsa.newkeys(1024)

    with open('keys/pubkey.pem', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    with open('keys/privkey.pem', 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

def load_keys():
    """Load RSA keys from files."""
    try:
        with open('keys/pubkey.pem', 'rb') as f:
            pubKey = rsa.PublicKey.load_pkcs1(f.read())

        with open('keys/privkey.pem', 'rb') as f:
            privKey = rsa.PrivateKey.load_pkcs1(f.read())

        return pubKey, privKey
    except FileNotFoundError as e:
        print(f"Key files not found: {e}")
        raise

def encrypt(msg, key):
    """Encrypt a message using the provided key."""
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciphertext, key):
    """Decrypt a ciphertext using the provided key."""
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except Exception as e:
        print(f"Error during decryption: {e}")
        return False

def sign_sha1(msg, key):
    """Sign a message using the provided key and SHA-1 algorithm."""
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    """Verify the signature of a message using the provided key."""
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except rsa.VerificationError as e:
        print(f"Error during verification: {e}")
        return False

def main():
    generate_keys()
    pubKey, privKey = load_keys()

    while True:
        choice = input("Would you like to (E)ncrypt, (D)ecrypt a message, or (Q)uit? ").strip().upper()

        if choice == 'E':
            message = input('Enter a message to encrypt: ')
            ciphertext = encrypt(message, pubKey)
            hex_ciphertext = ciphertext.hex()
            print(f'Encrypted message (ciphertext): {hex_ciphertext}')

            signature = sign_sha1(message, privKey)
            hex_signature = signature.hex()
            print(f'Signature: {hex_signature}')

            decrypt_choice = input("Would you like to decrypt the message now? (Y/N): ").strip().upper()
            if decrypt_choice == 'Y':
                try:
                    ciphertext = bytes.fromhex(hex_ciphertext)
                    decrypted_message = decrypt(ciphertext, privKey)
                    if decrypted_message:
                        print(f'Decrypted message: {decrypted_message}')

                        if verify_sha1(decrypted_message, signature, pubKey):
                            print('Signature verified!')
                        else:
                            print('Could not verify the message signature.')
                    else:
                        print('Could not decrypt the message.')
                except ValueError as ve:
                    print(f'Invalid input! Please ensure the ciphertext and signature are in proper hex format. Error: {ve}')

        elif choice == 'D':
            try:
                hex_ciphertext = input('Enter the ciphertext (hex format) to decrypt: ')
                ciphertext = bytes.fromhex(hex_ciphertext)

                decrypted_message = decrypt(ciphertext, privKey)
                if decrypted_message:
                    print(f'Decrypted message: {decrypted_message}')

                    hex_signature = input('Enter the signature (hex format) to verify: ')
                    signature = bytes.fromhex(hex_signature)
                    if verify_sha1(decrypted_message, signature, pubKey):
                        print('Signature verified!')
                    else:
                        print('Could not verify the message signature.')
                else:
                    print('Could not decrypt the message.')
            except ValueError as ve:
                print(f'Invalid input! Please ensure the ciphertext and signature are in proper hex format. Error: {ve}')

        elif choice == 'Q':
            print("Exiting the program.")
            break

        else:
            print('Invalid choice! Please enter "E" to encrypt, "D" to decrypt, or "Q" to quit.')

if __name__ == "__main__":
    main()
