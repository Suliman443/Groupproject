import sqlite3

DB_NAME = "tourism_app/events.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    with open("tourism_app/schema.sql") as f:
        conn = get_connection()
        conn.executescript(f.read())
        conn.commit()

def insert_event(title, description, location, date, image):
    conn = get_connection()
    conn.execute("INSERT INTO events (title, description, location, date, image) VALUES (?, ?, ?, ?, ?)",
                 (title, description, location, date, image))
    conn.commit()

def fetch_events():
    conn = get_connection()
    return conn.execute("SELECT * FROM events ORDER BY date").fetchall()
