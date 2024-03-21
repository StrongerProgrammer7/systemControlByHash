from backend.Hashs.Stribog import Stribog
from backend.utils import clear_and_write
from backend.Hashs.WorkHash import WorkHash
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
    checker = WorkHash(256,"STRIBOG")

    #checker.changeTypeHash(Hashs.SHA.value)
    checker.hashing_file("test_files/example2.txt")
    checker.hashing_file("test_files/example2.txt")
    #workHash(checker)
    #generateReport(checker)

    #checker = SHA(256, encryptMethod=None)
    #checker.deleteHashByPath("test_files/example2.txt")
    #checker.hashingFile("test_files/example2.txt")
    #workHash(checker)
    # checker.usingEncrypt(encryptMethod=EncryptMethods.AES)
    # workHash(checker)

