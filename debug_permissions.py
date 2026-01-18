import sqlite3
import os

DB_NAME = "inventory.db"

def check_user_permissions():
    if not os.path.exists(DB_NAME):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Find user with ID 4 or email containing 'shubham'
    print("--- Users ---")
    users = cursor.execute("SELECT id, company_name, email, role, access_inventory, access_calculator FROM users").fetchall()
    for user in users:
        print(f"ID: {user['id']}, Name: {user['company_name']}, Email: {user['email']}")
        print(f"Role: {user['role']} ({type(user['role'])})")
        print(f"Inv: {user['access_inventory']} ({type(user['access_inventory'])})")
        print(f"Calc: {user['access_calculator']} ({type(user['access_calculator'])})")
        print("-" * 20)

    conn.close()

if __name__ == "__main__":
    check_user_permissions()
