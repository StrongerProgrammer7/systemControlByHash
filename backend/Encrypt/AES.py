from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from backend.Encrypt.Encrypt import Encrypt
from Crypto.Random import get_random_bytes

class EncryptAES(Encrypt):
    def __init__(self, keyEncrypt=16):
        super().__init__(keyEncrypt)

    def encrypt_hash(self, hash_value):
        key = get_random_bytes(self.key)

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(hash_value.encode())
        return b64encode(ciphertext).decode('utf-8'), b64encode(cipher.nonce).decode('utf-8'), b64encode(tag).decode(
            'utf-8'), key

    def decrypt_hash(self, encrypted_hash, nonce, tag,key):
        cipher = AES.new(key, AES.MODE_GCM, b64decode(nonce))
        plaintext = cipher.decrypt_and_verify(b64decode(encrypted_hash), b64decode(tag))
        return plaintext.decode('utf-8')


'''
'''
