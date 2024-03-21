import sqlite3


class MyDatabase:
    conn = None
    cursor = None

    def __init__(self, db_name='mydatabase.db'):
        if MyDatabase.conn is None:
            print("Connect db...")
            MyDatabase.conn = sqlite3.connect(db_name)
            MyDatabase.cursor = MyDatabase.conn.cursor()

    def getCursor(self):
        return MyDatabase.cursor

    def getConnect(self):
        return MyDatabase.conn

    def create_table(self):
        MyDatabase.cursor.execute('''
            CREATE TABLE IF NOT EXISTS mytable (
                id INTEGER PRIMARY KEY,
                absolute_path TEXT UNIQUE,
                hash TEXT,
                encrypted_hash BLOB NULL,
                type_hash TEXT,
                type_encrypted TEXT NULL,
                iv BLOB NULL,
                hash_key_encrypted BLOB NULL,
                body_file BLOB NULL
            )
        ''')
        MyDatabase.conn.commit()

    # def __del__(self):
    #     MyDatabase.conn.close()
