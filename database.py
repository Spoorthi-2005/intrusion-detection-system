import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def add_user(username, email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, password))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = c.fetchone()
    conn.close()
    return user
