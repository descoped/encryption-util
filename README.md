# Rawdata Crypto Util

This is a utility API that provides AES GCM encryption and decryption of data. It requires a secret encryption key and salt.
Encrypt returns a byte array that contains an unique IV following ciphertext. 
Decrypt uses the IV to return plaintext.
  