"""Reflection test fixture."""

user_input = "email"

def test_reflection(obj):
    attr = getattr(obj, "authenticate")
    val = getattr(obj, user_input)
    setattr(obj, "role", "admin")
    setattr(obj, user_input, "value")
    g = globals()[user_input]
    l = locals()
    return attr, val
