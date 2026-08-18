"""FastAPI Application Test Fixture."""

from fastapi import FastAPI, Depends, Query
import sqlite3

app = FastAPI()

def get_db():
    return sqlite3.connect("test.db")

@app.get("/admin/delete_user")
def delete_user_admin(username: str = Query(...)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE name = '{username}'")
    return {"status": "deleted"}
