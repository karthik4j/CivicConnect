import sqlite3 
from werkzeug.security import generate_password_hash,check_password_hash
import uuid
conn = sqlite3.connect('database.db',check_same_thread=False)

def create_table():
  res = conn.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name=?;""", ('user',))
  table_exists = res.fetchone()
  if table_exists:
    return True
  else:
    res =conn.execute(f"CREATE TABLE {'user'} (id TEXT PRIMARY KEY,username TEXT, password TEXT)")
    print(res)

  
create_table()
username='Karthik'
user = conn.execute(f"SELECT username from user WHERE  username = '{username}'")
print(user.fetchone())
newid = uuid.uuid4()
pasword='bananas'
pasword = generate_password_hash(pasword)
res = conn.execute(f"INSERT INTO users values({newid},{user},{pasword})")