from Crypto.Cipher import AES

from overrides import overrides

from backend.Encrypt.Encrypt import Encrypt
from Crypto.Random import get_random_bytes


class EncryptAES(Encrypt):
    def __init__(self, keyEncrypt=16):
        super().__init__(keyEncrypt)

    @overrides
    def encrypt_hash(self, data):
        key = get_random_bytes(self.key)
        iv = get_random_bytes(self.key)

        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher.encrypt(data)
        return ciphertext, iv, key

    @overrides()
    def decrypt_hash(self, encrypted_data, iv, key):
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        plaintext = cipher.decrypt(encrypted_data)
        return plaintext.decode('utf-8')


'''
'''
