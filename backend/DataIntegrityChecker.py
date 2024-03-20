from Crypto.Hash import SHA256,SHA512 ,SHAKE128


from base64 import b64decode,b64encode
import os
import logging

import _pystribog
from backend.utils import size512Or256, _validate_type
from backend.enums.enumHash import Hashs
from backend.enums.enumEncryptMethod import EncryptMethods
from backend.Encrypt.AES import EncryptAES
from backend.Encrypt.DES import EncryptDES

class DataIntegrityChecker:

    def __init__(self, sizeHash, typeHash, keyEncrypt, encryptMethod):
        _validate_type(sizeHash, int, "sizeHash")
        _validate_type(keyEncrypt, int, "keyEncrypt")
        _validate_type(typeHash, Hashs, "typeHash")

        if not size512Or256(sizeHash):
            raise ValueError("Size hash must be 512 or 256")

        self._data = {}
        self.typeHash = typeHash
        self.sizeHash = sizeHash
        self.typeEncrypt = encryptMethod if encryptMethod is not None else None

        self._set_system_hash()
        self._set_system_encrypt(keyEncrypt) if encryptMethod is not None else None
        self._setup_logging()


    def hashingFile(self, file_path):
        if os.path.exists(file_path):
            print("")#"Overload methods")
        else:
            print(f"File '{file_path}' not found.")
            logging.error(f"File '{file_path}' not found.")
            return False

    def check_integrity(self, file_path):
        if file_path in self._data:
            print("")#"Overload methods")
        else:
            print(f"File '{file_path}' not found in integrity records.")
            logging.error(f"File '{file_path}' not found in integrity records.")

    def getHash(self,file_path):
        return self._data[file_path] if self.typeEncrypt is not None else None

    def getEncryptDataFile(self, file_path):
        return {
            self._data[file_path]['encrypted_hash'],
            self._data[file_path]['nonce'],
            self._data[file_path]['tag'],
        }

    def changeHashSize(self, size):
        if size != _pystribog.Hash256 and size != _pystribog.Hash512:
            print("Not correct size")
            return False
        self.sizeHash = size
        self._set_system_hash()

    def changeTypeHash(self, typeHash):
        _validate_type(typeHash, str, "typeHash")

        self.typeHash = typeHash
        self._set_system_hash()

    def getDifferenceFile(self, file_path):
        original_lines = self._read_file_lines("test_files/ex3.txt")
        current_lines = self._read_file_lines(file_path)
        differences = self._compare_lines(original_lines, current_lines)
        for diff in differences:
            print(diff)
        return differences

    def generate_report(self, report_file="data_integrity_report.txt"):
        with open(report_file, "w") as report:
            report.write("Data Integrity Report\n\n")
            for file_path, hash_info in self._data.items():
                report.write(f"File: {file_path}\n")
                report.write(f"Hash type: {self.typeHash.value}\n")
                if self.typeEncrypt is not None:
                    report.write(f"Type encrypt: {self.typeEncrypt.value}\n")
                    report.write(f"Hash Encrypted: {hash_info['encrypted_hash']}\n")
                report.write(f"Size hash = {512 if len(hash_info) == 128 else 256}\n")
                report.write(f"Hash Value: ")

                if os.path.exists(file_path):
                    with open(file_path, "rb") as file:
                        data = file.read()
                        newHash = self._get_hash_for_report(data, self._systemHash)
                        hash_value = self._getHash(self._getDecryptHash,file_path)
                        report.write(f"{hash_value} \n")
                        report.write(f"New hash {newHash}\n")
                        report.write("Status: ")
                        if newHash == hash_value:
                            report.write("Integrity verified\n")
                        else:
                            report.write("Integrity check failed\n")
                else:
                    report.write("File not found\n")
                report.write("\n")
        print(f"Report generated: {report_file}")

# private methods

    def _get_hash_for_report(self, data, hash_function):
        if self.typeHash == Hashs.SHA:
            hash_function = hash_function.new(data)
        elif self.typeHash == Hashs.STRIBOG:
            hash_function.clear()
            hash_function.update(data)
        elif self.typeHash == Hashs.SHAKE128:
            shake = self._systemHash.new()
            shake.update(data)
            shake128_hash = shake.read(self.sizeHash)
            return shake128_hash.hex()

        return hash_function.hexdigest()


    def _recordEncryptHash(self,hash_value,file_path):
        encryptHash, nonce, tag, key = self._encryptMethod.encrypt_hash(hash_value)

        self._data[file_path] = {
            'encrypted_hash': encryptHash,
            'nonce': nonce,
            'tag': tag,
            'key': b64encode(key).decode('utf-8')
        }

    def _getDecryptHash(self,file_path):
        return self._encryptMethod.decrypt_hash(self._data[file_path]['encrypted_hash'],
                           self._data[file_path]['nonce'],
                           self._data[file_path]['tag'],
                           b64decode(self._data[file_path]['key']))

    def _pushHashOrEncryptToData(self,callback,hash_value,file_path):
        if self.typeEncrypt is not None:
            callback(hash_value, file_path)
        else:
            self._data[file_path] = hash_value

    def _getHash(self,callback,file_path):
        if self.typeEncrypt is not None:
            return callback(file_path)
        else:
            return self._data[file_path]

    # for search diff in file======================
    def _read_file_lines(self,file_path):
        with open(file_path, "r") as file:
            return file.readlines()

    def _compare_lines(self,original_lines, current_lines):
        differences = []
        for i, (original_line, current_line) in enumerate(zip(original_lines, current_lines), start=1):
            differences.extend(self._compare_words_in_lines(original_line, current_line, i))
        return differences

    def _compare_words_in_lines(self,original_line, current_line, line_number):
        differences = []
        original_words = original_line.split()
        current_words = current_line.split()
        column_line = 0
        for j, (original_word, current_word) in enumerate(zip(original_words, current_words), start=1):
            if original_word != current_word:
                message,column_line = self._create_difference_message(original_word, current_word, line_number, j, column_line)
                differences.append(message)
            else:
                column_line += len(current_word) + 1
        return differences

    def _create_difference_message(self,original_word, current_word, line_number, word_number, column_line):
        if len(original_word) > len(current_word):
            return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}: 'len1{len(original_word)}' > 'len2{len(current_word)}' word: '{original_word}' vs '{current_word}'", column_line + len(current_word) + 1
        elif len(original_word) < len(current_word):
            return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}: 'len1{len(original_word)}' < 'len2{len(current_word)}' word: '{original_word}' vs '{current_word}'",column_line + len(current_word) + 1
        else:
            for k, (original_char, current_char) in enumerate(zip(original_word, current_word), start=1):
                column_line += 1
                if original_char != current_char:
                    return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}, num symbol {k} : '{original_char}' vs '{current_char}' word: '{original_word}' vs '{current_word}'", column_line + min(len(original_word), len(current_word)) - k + word_number - 1
            return ""  # Возвращаем пустую строку, если слова одинаковы
    # end search diff str

    def _set_system_hash(self):
        if self.typeHash == Hashs.STRIBOG:
            self._systemHash = _pystribog.StribogHash(self.sizeHash)
        elif self.typeHash == Hashs.SHA:
            self._systemHash = SHA256 if self.sizeHash == 256 else SHA512
        elif self.typeHash == Hashs.SHAKE128:
            self._systemHash = SHAKE128

    def _set_system_encrypt(self,key):
        if self.typeEncrypt == EncryptMethods.AES:
            self._encryptMethod = EncryptAES(key)
        elif self.typeEncrypt == EncryptMethods.DES:
            self._encryptMethod = EncryptDES(8)

    def _setup_logging(self):
        logging.basicConfig(filename='data_integrity.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')