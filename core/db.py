import sqlite3
import os

DB_PATH = "data/events.db"


def get_connection():
    os.makedirs("data", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device TEXT NOT NULL,
        domain TEXT NOT NULL,
        timestamp REAL NOT NULL,
        processed INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS domain_memory (
        domain TEXT PRIMARY KEY,
        first_seen REAL,
        last_seen REAL,
        query_count INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis (
        domain TEXT PRIMARY KEY,
        risk INTEGER,
        category TEXT,
        reason TEXT,
        model TEXT,
        analyzed_at REAL
    )
    """)

    conn.commit()
    conn.close()


def insert_event(device, domain, timestamp):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO events
    (device, domain, timestamp)
    VALUES (?, ?, ?)
    """,
    (device, domain, timestamp))

    cur.execute("""
    INSERT INTO domain_memory
    (domain, first_seen, last_seen, query_count)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(domain)
    DO UPDATE SET
        last_seen = excluded.last_seen,
        query_count = query_count + 1
    """,
    (domain, timestamp, timestamp))

    conn.commit()
    conn.close()


def get_events(limit=500):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT device, domain, timestamp
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """,
    (limit,))

    rows = cur.fetchall()
    conn.close()

    return rows
