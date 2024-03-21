import sqlite3

class MyDatabase:
    conn = None
    def __init__(self, db_name='mydatabase.db'):
        if MyDatabase.conn == None:
            MyDatabase.conn = sqlite3.connect(db_name)
        self.cursor = MyDatabase.conn.cursor()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS mytable (
                id INTEGER PRIMARY KEY,
                absolute_path TEXT UNIQUE,
                hash TEXT,
                encrypted_hash TEXT NULL,
                type_hash TEXT,
                type_encrypted TEXT NULL,
                extra_info_encryption TEXT NULL,
                hash_key_encrypted TEXT NULL,
                body_file BLOB
            )
        ''')
        MyDatabase.conn.commit()


    def __del__(self):
        MyDatabase.conn.close()

#
# if __name__ == "__main__":
#     db = MyDatabase()
#     db.create_table()
#
#     # Пример использования операций CRUD
#     db.insert_record('example_path', 'example_hash', encrypted_hash='example_encrypted_hash', type_hash='example_type_hash',extra_info_encryption = "aaa,aasd,assad")
#     record = db.get_record_by_absolute_path('example_path')
#     print("Retrieved Record:", record)
#     db.update_record_by_absolute_path('example_path', hash='updated_hash')
#     record = db.get_record_by_absolute_path('example_path')
#     print("Updated Record:", record)
#     db.delete_record_by_absolute_path('example_path')
