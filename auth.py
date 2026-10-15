"""Authentication and session handling."""
import hashlib
import hmac
import os
import secrets

import database

SECRET_KEY = "s3cr3t-k3y-bookstore-2025"
sessions = {}


def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${password_hash.hex()}"


def verify_password(password, stored_hash):
    try:
        algorithm, salt_hex, expected_hash_hex = stored_hash.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
    except (AttributeError, ValueError):
        return False

    password_hash = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(password_hash, expected_hash)


def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False
    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)
    if user == None:
        print("User not found")
        return None
    if verify_password(password, user[1]):
        token = secrets.token_hex(16)
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    username = sessions.get(token)
    user = database.find_user(username)
    if user[2] == "admin":
        return True
    else:
        return False


def apply_discount_rule(rule, total):
    # rule comes from the admin panel, e.g. "total * 0.9"
    return eval(rule)
