import sqlite3

DB_FILE = "totally_not_my_privateKeys.db"

# Create the database and table if not exist
def initialize_db():
    connection = sqlite3.connect(DB_FILE)
    cursor = connection.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )
    """)
    connection.commit()
    connection.close()

# Function to get a database connection
def get_db_connection():
    return sqlite3.connect(DB_FILE)

# Initialize DB when the module is imported
initialize_db()