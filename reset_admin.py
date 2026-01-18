
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "d:/Shubham/Shubham/neem_impex/inventory.db"

def reset_admin():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        

        # MANUAL MIGRATION: Add columns if they don't exist
        columns_to_add = [
            ("role", "TEXT DEFAULT 'user'"),
            ("access_inventory", "INTEGER DEFAULT 1"),
            ("access_calculator", "INTEGER DEFAULT 1")
        ]
        
        for col_name, col_type in columns_to_add:
            try:
                c.execute(f"SELECT {col_name} FROM users LIMIT 1")
            except sqlite3.OperationalError:
                print(f"Adding missing column: {col_name}...")
                c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")

        conn.commit()

        email = "admin@gmail.com"
        password = "Shubham1901"
        hashed_pw = generate_password_hash(password)
        
        print(f"Checking for user: {email}")
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        
        if user:
            print("User found. Updating password...")
            c.execute("UPDATE users SET password_hash = ?, role = 'admin', access_inventory=1, access_calculator=1 WHERE email = ?", (hashed_pw, email))
        else:
            print("User NOT found. Checking for old 'Shubham' user...")
            c.execute("SELECT * FROM users WHERE email = 'Shubham'")
            old_user = c.fetchone()
            if old_user:
                print("Old 'Shubham' user found. renaming and updating password...")
                c.execute("UPDATE users SET email = ?, password_hash = ?, role = 'admin', access_inventory=1, access_calculator=1 WHERE id = ?", (email, hashed_pw, old_user[0]))
            else:
                print("Creating new admin user...")
                c.execute("INSERT INTO users (company_name, email, password_hash, role, access_inventory, access_calculator) VALUES (?, ?, ?, ?, ?, ?)", 
                          ("Admin", email, hashed_pw, "admin", 1, 1))
        
        conn.commit()
        print("Success: Admin credentials have been reset to:")
        print(f"Email: {email}")
        print(f"Password: {password}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    reset_admin()
