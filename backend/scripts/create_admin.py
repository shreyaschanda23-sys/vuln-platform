"""
One-off script to create the first admin user. Run manually — no
self-registration endpoint exists by design for this internal tool.

Usage:
    python scripts/create_admin.py
"""
import sys
import os
import getpass

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from api.deps import SessionLocal
from app.security import hash_password
from models.user import User, UserRole


def create_admin():
    db = SessionLocal()
    try:
        email = input("Admin email: ").strip()
        if not email:
            print("Email is required.")
            return

        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"A user with email '{email}' already exists.")
            return

        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return
        if len(password) < 8:
            print("Password must be at least 8 characters.")
            return

        user = User(
            email=email,
            hashed_password=hash_password(password),
            role=UserRole.admin,
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Admin user '{email}' created successfully.")
    finally:
        db.close()


if __name__ == "__main__":
    create_admin()