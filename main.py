
from backend.SHA import SHA
from backend.Stribog import Stribog
from backend.utils import add_text_to_file

if __name__ == '__main__':
    checker = Stribog(256)

    checker.hashingFile("test_files/example2.txt")
   # checker.changeHashSize(256)
    checker.hashingFile("test_files/example.txt")

    add_text_to_file("test_files/example2.txt", "This is some additional text.\n")
    checker.check_integrity("test_files/example.txt")
   # checker.changeHashSize(512)
    checker.check_integrity("test_files/example2.txt")

    checker.generate_report()

'''
work with SHA
hash_object = SHA512.new(data)
hash_value = hash_object.hexdigest()
                
'''