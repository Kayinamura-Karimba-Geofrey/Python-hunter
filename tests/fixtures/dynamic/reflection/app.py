"""Reflection Test Fixture."""

class User:
    def __init__(self):
        self.email = "test@example.com"
        self.role = "admin"

user = User()
val = getattr(user, "email")
getattr(user, val)
setattr(user, "role", "user")
setattr(user, val, "hacked")
g = globals()
l = locals()
