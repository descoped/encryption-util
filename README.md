# Encryption Util

This is a utility API that provides AES CBC encryption and decryption of data and HMAC-SHA256 for integrity and
authenticity verification. It requires a secret encryption key and salt.
Encrypt returns a byte array that contains a unique IV following ciphertext.
Decrypt uses the IV to return plaintext.
