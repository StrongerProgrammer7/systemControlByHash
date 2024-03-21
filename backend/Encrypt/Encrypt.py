class Encrypt:
    def __init__(self, keyEncrypt):
        self.key = keyEncrypt

    def encrypt_hash(self, data):
        pass  # Overload

    def decrypt_hash(self, encrypted_data, iv, key):
        pass
