import os

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")

ADMIN_EMAIL_ADDRESS = os.getenv("ADMIN_EMAIL_ADDRESS")
ADMIN_EMAIL_PASSWORD = os.getenv("ADMIN_EMAIL_PASSWORD")

reserved_keywords = [
    "parijat",
    "sanskrit",
    "vishnu",
    "shiva",
    "krishna",
    "panini",
    "om"
]