from backend.SHA import SHA
from backend.Stribog import Stribog,EncryptMethods
from backend.SHAKE import SHAKE
from backend.utils import add_text_to_file, clear_and_write

def workHash(hash):
    hash.hashingFile("test_files/example2.txt")
    # hash.changeHashSize(256)
    hash.hashingFile("test_files/example.txt")

    clear_and_write("test_files/example2.txt", "test_files/ex3.txt")
    #input("Измени файл example2: ")
    #add_text_to_file("test_files/example2.txt", "This is some additional text:\n")
    hash.check_integrity("test_files/example.txt")
    # hash.changeHashSize(512)
    hash.check_integrity("test_files/example2.txt")
    #print(hash.getDataFile("test_files/example2.txt"))

def generateReport(hash):
    hash.generate_report()

if __name__ == '__main__':
    checker = Stribog(256,encryptMethod=None)

    #workHash(checker)
    generateReport(checker)

    #checker = SHA(256, encryptMethod=None)
    #workHash(checker)
    # checker.usingEncrypt(encryptMethod=EncryptMethods.AES)
    # workHash(checker)

