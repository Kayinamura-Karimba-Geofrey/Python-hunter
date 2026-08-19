"""FastAPI web security fixture."""

from fastapi import FastAPI, Depends
import jwt
import requests

app = FastAPI()

def get_current_user():
    return {"user_id": 1, "role": "admin"}

@app.get("/public/ping")
def ping():
    return {"status": "ok"}

@app.get("/users/{user_id}")
def get_user_profile(user_id: int):
    return {"user_id": user_id, "email": "user@example.com"}

@app.post("/fetch")
def fetch_url(url: str):
    res = requests.get(url)
    return {"content": res.text}

@app.post("/login")
def login(token: str):
    payload = jwt.decode(token, "secret", options={"verify_signature": False})
    return payload
