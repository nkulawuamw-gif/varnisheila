import os
import json
import hashlib
import secrets
import logging
from datetime import datetime
from functools import wraps

import bleach
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, jsonify
)

import firebase_admin
from firebase_admin import credentials, firestore


# =========================
# APP SETUP
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.debug = os.environ.get("DEBUG", "False") == "True"


# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =========================
# FIREBASE INIT (FIXED FOR RENDER)
# =========================
_firebase_db = None
_firebase_initialized = False


def init_firebase():
    global _firebase_db, _firebase_initialized

    if _firebase_initialized:
        return _firebase_db

    try:
        firebase_json = json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT"])

        if not firebase_admin._apps:
            cred = credentials.Certificate(firebase_json)
            firebase_admin.initialize_app(cred)

        _firebase_db = firestore.client()
        _firebase_initialized = True

        logger.info("Firebase initialized successfully")

    except Exception as e:
        logger.error(f"Firebase init failed: {e}")
        _firebase_db = None

    return _firebase_db


def get_db():
    return init_firebase()


def safe_get_db():
    db = get_db()
    if db is None:
        raise Exception("Firebase not initialized. Check Render environment variable.")
    return db


# =========================
# COLLECTIONS
# =========================
COL_USERS = "users"
COL_PRODUCTS = "products"


# =========================
# HELPERS
# =========================
def hash_password(password):
    salt = secrets.token_hex(16)
    return salt + "$" + hashlib.sha256((salt + password).encode()).hexdigest()


def check_password(password, stored):
    salt, h = stored.split("$")
    return hashlib.sha256((salt + password).encode()).hexdigest() == h


def sanitize(text):
    return bleach.clean(text, strip=True)


def get_all(collection):
    db = safe_get_db()
    docs = db.collection(collection).stream()
    result = []
    for d in docs:
        data = d.to_dict()
        data["id"] = d.id
        result.append(data)
    return result


def add_doc(collection, doc_id, data):
    db = safe_get_db()
    db.collection(collection).document(doc_id).set(data)


def delete_doc(collection, doc_id):
    db = safe_get_db()
    db.collection(collection).document(doc_id).delete()


def generate_id(prefix, collection):
    items = get_all(collection)
    max_num = 0

    for i in items:
        if i["id"].startswith(prefix):
            try:
                max_num = max(max_num, int(i["id"].replace(prefix, "")))
            except:
                pass

    return f"{prefix}{max_num+1:03d}"


# =========================
# ADMIN SEED (FIX FOR RENDER LOGIN ISSUE)
# =========================
def seed_admin():
    db = get_db()
    if not db:
        return

    users = list(db.collection(COL_USERS).stream())

    if len(users) == 0:
        db.collection(COL_USERS).document("U001").set({
            "id": "U001",
            "full_name": "Admin",
            "username": "admin",
            "password": hash_password("admin123"),
            "role": "admin",
            "date_created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        print("Default admin created: admin / admin123")


# =========================
# AUTH
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    return redirect("/dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize(request.form.get("username"))
        password = request.form.get("password")

        users = get_all(COL_USERS)

        for u in users:
            if u["username"] == username and check_password(password, u["password"]):
                session["user_id"] = u["id"]
                session["role"] = u["role"]
                session["username"] = u["username"]
                return redirect("/dashboard")

        flash("Invalid credentials")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    products = get_all(COL_PRODUCTS)
    return render_template("dashboard.html", products=products)


@app.route("/products")
@login_required
def products():
    return render_template("products.html", products=get_all(COL_PRODUCTS))


@app.route("/products/add", methods=["POST"])
@login_required
def add_product():
    name = sanitize(request.form.get("name"))
    qty = int(request.form.get("quantity", 0))

    pid = generate_id("P", COL_PRODUCTS)

    add_doc(COL_PRODUCTS, pid, {
        "name": name,
        "quantity": qty
    })

    return redirect("/products")


@app.route("/products/delete/<pid>")
@login_required
def delete_product(pid):
    delete_doc(COL_PRODUCTS, pid)
    return redirect("/products")


# =========================
# STARTUP
# =========================
if __name__ == "__main__":
    with app.app_context():
        seed_admin()

    app.run(host="0.0.0.0", port=5000)