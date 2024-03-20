#from Crypto.Hash import SHA512

from backend.DataIntegrityChecker import DataIntegrityChecker
from backend.utils import add_text_to_file

if __name__ == '__main__':
    checker = DataIntegrityChecker()

    checker.hashingFile("test_files/example.txt")
    checker.hashingFile("test_files/example2.txt")

    add_text_to_file("test_files/example2.txt", "This is some additional text.\n")

    checker.check_integrity("test_files/example2.txt")
    checker.check_integrity("test_files/example.txt")

'''
work with SHA
hash_object = SHA512.new(data)
hash_value = hash_object.hexdigest()
                
'''