import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(64).hex())
    FIREBASE_CREDENTIALS = os.environ.get(
        "FIREBASE_CREDENTIALS",
        os.path.join(BASE_DIR, "private", "firebase-key.json"),
    )
    DEBUG = os.environ.get("FLASK_DEBUG", "").lower() == "true"
