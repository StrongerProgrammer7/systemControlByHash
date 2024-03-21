from Crypto.Cipher import DES
from overrides import overrides

from backend.Encrypt.Encrypt import Encrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class EncryptDES(Encrypt):
    def __init__(self, keyEncrypt=8):
        super().__init__(keyEncrypt)

    @overrides
    def encrypt_hash(self, data):
        key = get_random_bytes(self.key)
        iv = get_random_bytes(DES.block_size)  # IV size is equal to block size (8 bytes for DES)
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        ciphertext = cipher.encrypt(pad(data, DES.block_size))
        return ciphertext,iv,key

    @overrides()
    def decrypt_hash(self, encrypted_data, iv, key):
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        plaintext = unpad(cipher.decrypt(encrypted_data), DES.block_size)
        return plaintext
