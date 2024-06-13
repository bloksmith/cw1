import sqlite3
import uuid

def fix_invalid_uuids(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM quantumapp_pool")
    rows = cursor.fetchall()

    for row in rows:
        pool_id = row[0]
        try:
            uuid.UUID(pool_id)
        except ValueError:
            new_uuid = str(uuid.uuid4())
            print(f"Fixing invalid UUID: {pool_id} -> {new_uuid}")
            cursor.execute("UPDATE quantumapp_pool SET id = ? WHERE id = ?", (new_uuid, pool_id))
            conn.commit()

    conn.close()

# Path to your SQLite database
db_path = 'db.sqlite3.db'
fix_invalid_uuids(db_path)
