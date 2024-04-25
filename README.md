# Vigenere Cipher Python Implementation

This repository contains Python code for implementing the Vigenere Cipher.

## Description

The Vigenere Cipher is a polyalphabetic substitution cipher that uses a keyword to encrypt and decrypt text. It is more secure than the Caesar Cipher because it uses multiple alphabets to encode the message. This implementation includes encryption, decryption, and cryptanalysis functions for the Vigenere Cipher.

## Features

- Encryption of plaintext using a given key
- Decryption of ciphertext using a given key
- Automatic key generation for encryption (autokey method)
- Running key encryption
- Cryptanalysis functions for key length detection and key recovery

## Contents

- `vigenere.py`: Python script containing the Vigenere Cipher implementation.
- `utilities.py`: Python script containing utility functions used in the Vigenere Cipher implementation.
- `README.md`: This file, providing an overview of the project.

## Usage

To use the Vigenere Cipher implementation, you can import the `Vigenere` class from `vigenere.py` and create an instance with a key. Then you can encrypt or decrypt text using the provided methods.

Example usage:
```python
from vigenere import Vigenere

# Create a Vigenere cipher instance with key 'key'
cipher = Vigenere('key')

# Encrypt plaintext
encrypted_text = cipher.encrypt('hello')

# Decrypt ciphertext
decrypted_text = cipher.decrypt(encrypted_text)

print("Encrypted:", encrypted_text)
print("Decrypted:", decrypted_text)
