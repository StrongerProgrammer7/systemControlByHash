from Crypto.Cipher import DES
from backend.Encrypt.Encrypt import Encrypt
from Crypto.Random import get_random_bytes


class EncryptDES(Encrypt):
    def __init__(self, keyEncrypt=8):
        super().__init__(keyEncrypt)

    def encrypt_hash(self, hash_value):
        key = get_random_bytes(self.key)
        iv = get_random_bytes(DES.block_size)  # IV size is equal to block size (8 bytes for DES)
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        encrypted_hash = cipher.encrypt(hash_value.encode())

        return encrypted_hash, iv, "", key

    def decrypt_hash(self, encrypted_hash, iv, tag, key):
        cipher = DES.new(key, DES.MODE_CFB, iv=iv)
        decrypted_hash = cipher.decrypt(encrypted_hash)
        return decrypted_hash.decode('utf-8')
