import psycopg2
from Hash.SHA import hash

class Authenticator:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Authenticator, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self) -> None:
        self.conn = psycopg2.connect(host="localhost", dbname="postgres",user="postgres", password="admin@1234", port="5432")
        self.cur = self.conn.cursor()
        
    def __del__(self):
        self.cur.close()
        self.conn.close()
        
    def authenticate_user(self, username, password):
        password_hash = hash(password).hex()
        # Execute the query to fetch all users
        self.cur.execute(""" SELECT username, password_hash FROM public."UA_DB" """)
        
        # Fetch all rows
        rows = self.cur.fetchall()

        # check if the user is in records
        for row in rows:
            db_username, db_password_hash = row
            if username == db_username and password_hash==db_password_hash[2:]:
                return True
        return False
    
    def add_new_user(self, username, password):
        # 1. check that the username doesnt already exists
        # Execute the query to fetch all users
        self.cur.execute(""" SELECT username FROM public."UA_DB" """)
        
        # Fetch all rows
        rows = self.cur.fetchall()
        for row in rows:
            if row[0] == username:
                return "Username Already Exsists! Try using another username."
        # 2. add the username and hash of the password to the database
        try:
            # Execute the SQL statement to insert the user into the table
            self.cur.execute(""" INSERT INTO public."UA_DB" (username, password_hash) VALUES (%s, %s)""", (username, hash(password)))

            # Commit the transaction
            self.conn.commit()
            return "User added successfully."
        
        except psycopg2.Error as e:
            print("Error:", e)
            

if __name__ == "__main__":
    auth = Authenticator()
    print(auth.authenticate_user("admin", "admin@1234"))
    print(auth.add_new_user("admin", "admin@1234"))
    print(auth.authenticate_user("admin", "admin@1234"))
    print(auth.authenticate_user("admin", "admin@_1234"))
    print(auth.add_new_user("admin2", "admin"))
    