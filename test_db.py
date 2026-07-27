from app.database import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) AS total FROM scan_history")

print(cursor.fetchone()["total"])

conn.close()