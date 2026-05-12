import os
import json
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(64).hex())
    DEBUG = os.environ.get("FLASK_DEBUG", "").lower() == "true"

    FIREBASE_CREDENTIALS = os.environ.get(
        "FIREBASE_CREDENTIALS",
        os.path.join(BASE_DIR, "private", "firebase-key.json"),
    )

    _firebase_cred = None

    @classmethod
    def get_firebase_cred(cls):
        if cls._firebase_cred:
            return cls._firebase_cred
        json_str = os.environ.get("FIREBASE_CREDENTIALS_JSON")
        if json_str:
            data = json.loads(json_str)
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            json.dump(data, tmp)
            tmp.close()
            cls._firebase_cred = tmp.name
            return cls._firebase_cred
        cls._firebase_cred = cls.FIREBASE_CREDENTIALS
        return cls._firebase_cred
