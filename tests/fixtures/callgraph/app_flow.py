"""Synthetic application for call graph and reachability testing."""

from flask import request


def recursive_helper(n: int) -> int:
    if n <= 1:
        return 1
    return n * recursive_helper(n - 1)


class UserRepository:
    def find_user(self, username: str):
        cursor.execute("SELECT * FROM users WHERE name = " + username)


class UserService:
    def __init__(self):
        self.repo = UserRepository()

    def get_user(self, username: str):
        return self.repo.find_user(username)


def user_controller():
    username = request.args.get("username")
    service = UserService()
    return service.get_user(username)


@app.get("/users")
def get_user_route():
    return user_controller()
