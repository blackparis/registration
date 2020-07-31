import os

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")

USERNAME_SMTP = os.getenv("USERNAME_SMTP")
PASSWORD_SMTP = os.getenv("PASSWORD_SMTP")
SMTP_HOST = os.getenv("SMTP_HOST")

reserved_keywords = [
    "parijat",
    "sanskrit",
    "vishnu",
    "shiva",
    "krishna",
    "panini",
    "om"
]