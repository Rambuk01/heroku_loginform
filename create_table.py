import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

c.execute('''CREATE TABLE user
          (id integer PRIMARY KEY AUTOINCREMENT, username text, password text)''')

conn.commit()
conn.close()