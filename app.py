import os
import json
import hashlib
import secrets
import logging
from datetime import datetime
from functools import wraps

import bleach
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    jsonify,
)

from config import Config
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
app.debug = Config.DEBUG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_firebase_db = None
_firebase_initialized = False

COL_PRODUCTS = "products"
COL_STOCK_IN = "stock_in"
COL_STOCK_OUT = "stock_out"
COL_USERS = "users"
COL_SHOPS = "shops"
COL_SHOP_STOCK = "shop_stock"
COL_SALES = "sales"


def get_db():
    global _firebase_db, _firebase_initialized
    if _firebase_db is None:
        try:
            cred = credentials.Certificate(Config.FIREBASE_CREDENTIALS)
            firebase_admin.initialize_app(cred)
            _firebase_db = firestore.client()
            _firebase_initialized = True
            _seed_if_empty()
        except Exception as e:
            logger.error("Firebase init failed: %s", e)
    return _firebase_db


def seed_defaults():
    db = get_db()
    if not db:
        return

    if not list(db.collection(COL_USERS).limit(1).stream()):
        default_pw = hash_password("admin123")
        db.collection(COL_USERS).document("U001").set({
            "id": "U001",
            "full_name": "Admin",
            "username": "admin",
            "password": default_pw,
            "role": "admin",
            "date_created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        logger.info("Default admin user created")


_seed_done = False


def _seed_if_empty():
    global _seed_done
    if _seed_done:
        return
    try:
        seed_defaults()
        _seed_done = True
    except Exception as e:
        logger.error("Seed failed: %s", e)


def safe_get_db():
    return get_db()


def get_all(collection):
    db = safe_get_db()
    if not db:
        return []
    try:
        docs = db.collection(collection).stream()
        result = []
        for doc in docs:
            data = doc.to_dict()
            if data:
                data["id"] = doc.id
                result.append(data)
        return result
    except Exception as e:
        logger.error("Error reading %s: %s", collection, e)
        return []


def get_by_field(collection, field, value):
    db = safe_get_db()
    if not db:
        return []
    try:
        docs = db.collection(collection).where(field, "==", value).stream()
        result = []
        for doc in docs:
            data = doc.to_dict()
            if data:
                data["id"] = doc.id
                result.append(data)
        return result
    except Exception as e:
        logger.error("Error querying %s: %s", collection, e)
        return []


def add_doc(collection, doc_id, data):
    db = safe_get_db()
    if not db:
        return
    try:
        data["id"] = doc_id
        db.collection(collection).document(doc_id).set(data)
    except Exception as e:
        logger.error("Error adding to %s: %s", collection, e)


def update_doc(collection, doc_id, data):
    db = safe_get_db()
    if not db:
        return
    try:
        db.collection(collection).document(doc_id).update(data)
    except Exception as e:
        logger.error("Error updating %s: %s", collection, e)


def delete_doc(collection, doc_id):
    db = safe_get_db()
    if not db:
        return
    try:
        db.collection(collection).document(doc_id).delete()
    except Exception as e:
        logger.error("Error deleting from %s: %s", collection, e)


def generate_id(prefix, collection):
    docs = get_all(collection)
    max_num = 0
    for doc in docs:
        doc_id = doc.get("id", "")
        if doc_id.startswith(prefix):
            try:
                num = int(doc_id[len(prefix):])
                if num > max_num:
                    max_num = num
            except ValueError:
                pass
    return f"{prefix}{max_num + 1:03d}"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first", "danger")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def sanitize_html(text):
    return bleach.clean(text, tags=[], strip=True)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def check_password(password, stored):
    if "$" in stored:
        salt, h = stored.split("$", 1)
        return hash_password(password, salt) == stored
    return hashlib.sha256(password.encode()).hexdigest() == stored


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf():
    token = request.form.get("_csrf_token")
    if not token or token != session.get("_csrf_token"):
        flash("Session expired or invalid request. Please try again.", "danger")
        return False
    return True


@app.before_request
def ensure_session():
    generate_csrf_token()


@app.context_processor
def inject_user():
    shops_list = []
    try:
        shops_list = [
            {"id": s["id"], "name": s["name"]}
            for s in get_all(COL_SHOPS)
            if s.get("name")
        ]
    except Exception:
        pass
    return {
        "shops_list": shops_list,
        "csrf_token": session.get("_csrf_token", ""),
        "db_error": "" if safe_get_db() else "Cannot connect to Firebase. Check your credentials.",
    }


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = sanitize_html(request.form.get("username", ""))
        password = request.form.get("password", "")
        users = get_all(COL_USERS)
        for u in users:
            if u.get("username") == username and check_password(password, u.get("password", "")):
                session.permanent = True
                session["user_id"] = u.get("id", "")
                session["username"] = u.get("username", "")
                session["full_name"] = u.get("full_name", "")
                session["role"] = u.get("role", "")
                flash(f"Welcome, {u.get('full_name', username)}!", "success")
                return redirect(url_for("dashboard"))
        flash("Invalid username or password", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    products = get_all(COL_PRODUCTS)
    stockin = get_all(COL_STOCK_IN)
    stockout = get_all(COL_STOCK_OUT)

    total_products = len(products)
    total_qty = 0
    low_stock_count = 0

    for p in products:
        qty = int(p.get("quantity", 0))
        total_qty += qty
        reorder = int(p.get("reorder_level", 0))
        if qty <= reorder:
            low_stock_count += 1

    recent_in = sorted(
        [r for r in stockin if r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )[:5]

    recent_out = sorted(
        [r for r in stockout if r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )[:5]

    return render_template(
        "dashboard.html",
        total_products=total_products,
        total_qty=total_qty,
        low_stock_count=low_stock_count,
        recent_in=recent_in,
        recent_out=recent_out,
    )


@app.route("/products")
@login_required
def products():
    all_data = get_all(COL_PRODUCTS)
    search = request.args.get("search", "").lower()
    products_list = []

    for p in all_data:
        name = p.get("name", "")
        category = p.get("category", "")
        if search and search not in name.lower() and search not in category.lower():
            continue
        qty = int(p.get("quantity", 0))
        reorder = int(p.get("reorder_level", 0))
        products_list.append({
            "id": p.get("id", ""),
            "name": name,
            "category": category,
            "unit": p.get("unit", ""),
            "buying_price": p.get("buying_price", "0"),
            "selling_price": p.get("selling_price", "0"),
            "quantity": qty,
            "reorder_level": reorder,
            "date_added": p.get("date_added", ""),
            "low_stock": qty <= reorder,
        })

    return render_template("products.html", products=products_list, search=search)


@app.route("/products/add", methods=["POST"])
@login_required
def add_product():
    if not validate_csrf():
        return redirect(url_for("products"))
    name = sanitize_html(request.form.get("name", ""))
    category = sanitize_html(request.form.get("category", ""))
    unit = sanitize_html(request.form.get("unit", ""))
    buying_price = sanitize_html(request.form.get("buying_price", "0"))
    selling_price = sanitize_html(request.form.get("selling_price", "0"))
    quantity = sanitize_html(request.form.get("quantity", "0"))
    reorder_level = sanitize_html(request.form.get("reorder_level", "0"))

    if not name:
        flash("Product name is required", "danger")
        return redirect(url_for("products"))

    try:
        buying_price = float(buying_price)
        selling_price = float(selling_price)
        quantity = int(quantity)
        reorder_level = int(reorder_level)
        if buying_price < 0 or selling_price < 0 or quantity < 0 or reorder_level < 0:
            raise ValueError
    except (ValueError, TypeError):
        flash("Prices and quantities must be valid non-negative numbers", "danger")
        return redirect(url_for("products"))

    pid = generate_id("P", COL_PRODUCTS)
    date_added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    add_doc(COL_PRODUCTS, pid, {
        "name": name,
        "category": category,
        "unit": unit,
        "buying_price": str(buying_price),
        "selling_price": str(selling_price),
        "quantity": quantity,
        "reorder_level": reorder_level,
        "date_added": date_added,
    })
    flash(f"Product '{name}' added successfully!", "success")
    return redirect(url_for("products"))


@app.route("/products/edit", methods=["POST"])
@login_required
def edit_product():
    if not validate_csrf():
        return redirect(url_for("products"))
    pid = sanitize_html(request.form.get("pid", ""))
    name = sanitize_html(request.form.get("name", ""))
    category = sanitize_html(request.form.get("category", ""))
    unit = sanitize_html(request.form.get("unit", ""))
    buying_price = sanitize_html(request.form.get("buying_price", "0"))
    selling_price = sanitize_html(request.form.get("selling_price", "0"))
    quantity = sanitize_html(request.form.get("quantity", "0"))
    reorder_level = sanitize_html(request.form.get("reorder_level", "0"))

    if not pid or not name:
        flash("Product ID and name are required", "danger")
        return redirect(url_for("products"))

    try:
        buying_price = float(buying_price)
        selling_price = float(selling_price)
        quantity = int(quantity)
        reorder_level = int(reorder_level)
        if buying_price < 0 or selling_price < 0 or quantity < 0 or reorder_level < 0:
            raise ValueError
    except (ValueError, TypeError):
        flash("Prices and quantities must be valid non-negative numbers", "danger")
        return redirect(url_for("products"))

    doc = safe_get_db().collection(COL_PRODUCTS).document(pid).get()
    if doc.exists:
        update_doc(COL_PRODUCTS, pid, {
            "name": name,
            "category": category,
            "unit": unit,
            "buying_price": str(buying_price),
            "selling_price": str(selling_price),
            "quantity": quantity,
            "reorder_level": reorder_level,
        })
        flash(f"Product '{name}' updated!", "success")
    else:
        flash("Product not found", "danger")
    return redirect(url_for("products"))


@app.route("/products/delete/<pid>")
@login_required
def delete_product(pid):
    doc = safe_get_db().collection(COL_PRODUCTS).document(pid).get()
    if doc.exists:
        delete_doc(COL_PRODUCTS, pid)
        flash("Product deleted!", "success")
    else:
        flash("Product not found", "danger")
    return redirect(url_for("products"))


@app.route("/products/get/<pid>")
@login_required
def get_product(pid):
    doc = safe_get_db().collection(COL_PRODUCTS).document(pid).get()
    if doc.exists:
        data = doc.to_dict()
        return jsonify(data)
    return jsonify({"error": "Not found"}), 404


@app.route("/stock-in")
@login_required
def stock_in():
    all_data = get_all(COL_STOCK_IN)
    products = get_all(COL_PRODUCTS)

    product_list = [
        {"id": p.get("id", ""), "name": p.get("name", ""), "quantity": p.get("quantity", 0)}
        for p in products
    ]

    records = sorted(
        [r for r in all_data if r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )

    return render_template("stock_in.html", records=records, products=product_list)


@app.route("/stock-in/add", methods=["POST"])
@login_required
def add_stock_in():
    if not validate_csrf():
        return redirect(url_for("stock_in"))
    product_id = sanitize_html(request.form.get("product_id", ""))
    quantity = request.form.get("quantity", "0")
    supplier = sanitize_html(request.form.get("supplier", ""))
    purchase_date = sanitize_html(request.form.get("purchase_date", ""))

    if not product_id or not quantity:
        flash("Product and quantity are required", "danger")
        return redirect(url_for("stock_in"))

    try:
        qty_added = int(quantity)
        if qty_added <= 0:
            flash("Quantity must be positive", "danger")
            return redirect(url_for("stock_in"))
    except ValueError:
        flash("Invalid quantity", "danger")
        return redirect(url_for("stock_in"))

    db = safe_get_db()
    doc = db.collection(COL_PRODUCTS).document(product_id).get()
    if not doc.exists:
        flash("Product not found", "danger")
        return redirect(url_for("stock_in"))

    product = doc.to_dict()
    product_name = product.get("name", "")
    current_qty = int(product.get("quantity", 0))
    new_qty = current_qty + qty_added
    update_doc(COL_PRODUCTS, product_id, {"quantity": new_qty})

    tid = generate_id("SI", COL_STOCK_IN)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    added_by = session.get("full_name", "Staff")

    add_doc(COL_STOCK_IN, tid, {
        "product_id": product_id,
        "product_name": product_name,
        "qty": qty_added,
        "supplier": supplier,
        "purchase_date": purchase_date,
        "added_by": added_by,
        "timestamp": timestamp,
    })
    flash(f"Stock In: {qty_added} {product_name} added!", "success")
    return redirect(url_for("stock_in"))


@app.route("/stock-out")
@login_required
def stock_out():
    all_data = get_all(COL_STOCK_OUT)
    products = get_all(COL_PRODUCTS)

    product_list = [
        {"id": p.get("id", ""), "name": p.get("name", ""), "quantity": p.get("quantity", 0)}
        for p in products
    ]

    records = sorted(
        [r for r in all_data if r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )

    return render_template("stock_out.html", records=records, products=product_list)


@app.route("/stock-out/add", methods=["POST"])
@login_required
def add_stock_out():
    if not validate_csrf():
        return redirect(url_for("stock_out"))
    product_id = sanitize_html(request.form.get("product_id", ""))
    quantity = request.form.get("quantity", "0")
    customer = sanitize_html(request.form.get("customer", ""))
    reason = sanitize_html(request.form.get("reason", "sale"))

    if not product_id or not quantity:
        flash("Product and quantity are required", "danger")
        return redirect(url_for("stock_out"))

    try:
        qty_removed = int(quantity)
        if qty_removed <= 0:
            flash("Quantity must be positive", "danger")
            return redirect(url_for("stock_out"))
    except ValueError:
        flash("Invalid quantity", "danger")
        return redirect(url_for("stock_out"))

    db = safe_get_db()
    doc = db.collection(COL_PRODUCTS).document(product_id).get()
    if not doc.exists:
        flash("Product not found", "danger")
        return redirect(url_for("stock_out"))

    product = doc.to_dict()
    product_name = product.get("name", "")
    current_qty = int(product.get("quantity", 0))

    if qty_removed > current_qty:
        flash(f"Insufficient stock! Only {current_qty} available", "danger")
        return redirect(url_for("stock_out"))

    new_qty = current_qty - qty_removed
    update_doc(COL_PRODUCTS, product_id, {"quantity": new_qty})

    tid = generate_id("SO", COL_STOCK_OUT)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    removed_by = session.get("full_name", "Staff")

    add_doc(COL_STOCK_OUT, tid, {
        "product_id": product_id,
        "product_name": product_name,
        "qty": qty_removed,
        "customer": customer,
        "reason": reason,
        "removed_by": removed_by,
        "timestamp": timestamp,
    })
    flash(f"Stock Out: {qty_removed} {product_name} removed!", "success")
    return redirect(url_for("stock_out"))


@app.route("/low-stock")
@login_required
def low_stock():
    products = get_all(COL_PRODUCTS)
    low_items = []
    for p in products:
        qty = int(p.get("quantity", 0))
        reorder = int(p.get("reorder_level", 0))
        if qty <= reorder:
            low_items.append({
                "id": p.get("id", ""),
                "name": p.get("name", ""),
                "category": p.get("category", ""),
                "quantity": qty,
                "reorder_level": reorder,
                "unit": p.get("unit", ""),
            })
    return render_template("low_stock.html", items=low_items)


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")


@app.route("/reports/stock")
@login_required
def report_stock():
    products = get_all(COL_PRODUCTS)
    data = []
    for p in products:
        data.append({
            "Product ID": p.get("id", ""),
            "Product Name": p.get("name", ""),
            "Category": p.get("category", ""),
            "Unit": p.get("unit", ""),
            "Buying Price": p.get("buying_price", "0"),
            "Selling Price": p.get("selling_price", "0"),
            "Quantity": str(p.get("quantity", 0)),
            "Reorder Level": str(p.get("reorder_level", 0)),
        })
    headers = list(data[0].keys()) if data else []
    return render_template("reports_table.html", title="Stock Report", headers=headers, data=data)


@app.route("/reports/low-stock")
@login_required
def report_low_stock():
    products = get_all(COL_PRODUCTS)
    data = []
    for p in products:
        qty = int(p.get("quantity", 0))
        reorder = int(p.get("reorder_level", 0))
        if qty <= reorder:
            data.append({
                "Product ID": p.get("id", ""),
                "Product Name": p.get("name", ""),
                "Category": p.get("category", ""),
                "Quantity": str(qty),
                "Reorder Level": str(reorder),
            })
    headers = list(data[0].keys()) if data else []
    return render_template("reports_table.html", title="Low Stock Report", headers=headers, data=data)


@app.route("/reports/stock-in")
@login_required
def report_stock_in():
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    shop_id = request.args.get("shop", "")

    shops_data = get_all(COL_SHOPS)
    shops_list = [{"id": s.get("id", ""), "name": s.get("name", "")} for s in shops_data]

    if shop_id:
        all_data = get_all(COL_SHOP_STOCK)
        data = []
        for r in sorted(all_data, key=lambda x: x.get("timestamp", ""), reverse=True):
            if r.get("shop_id") != shop_id:
                continue
            ts = r.get("timestamp", "")
            if date_from and ts < date_from:
                continue
            if date_to and ts > date_to + " 23:59:59":
                continue
            data.append({
                "Transaction ID": r.get("id", ""),
                "Shop": r.get("shop_name", ""),
                "Product Name": r.get("product_name", ""),
                "Quantity": str(r.get("qty", 0)),
                "Received By": r.get("transferred_by", ""),
                "Timestamp": ts,
            })
    else:
        all_data = get_all(COL_STOCK_IN)
        data = []
        for r in sorted(all_data, key=lambda x: x.get("timestamp", ""), reverse=True):
            ts = r.get("timestamp", "")
            if date_from and ts < date_from:
                continue
            if date_to and ts > date_to + " 23:59:59":
                continue
            data.append({
                "Transaction ID": r.get("id", ""),
                "Product ID": r.get("product_id", ""),
                "Product Name": r.get("product_name", ""),
                "Quantity Added": str(r.get("qty", 0)),
                "Supplier": r.get("supplier", ""),
                "Purchase Date": r.get("purchase_date", ""),
                "Added By": r.get("added_by", ""),
                "Timestamp": ts,
            })
    headers = list(data[0].keys()) if data else []
    return render_template("reports_table.html", title="Stock In Report", headers=headers, data=data, date_from=date_from, date_to=date_to, shops=shops_list, shop_id=shop_id)


@app.route("/reports/stock-out")
@login_required
def report_stock_out():
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    shop_id = request.args.get("shop", "")

    shops_data = get_all(COL_SHOPS)
    shops_list = [{"id": s.get("id", ""), "name": s.get("name", "")} for s in shops_data]

    is_admin = session.get("role") == "admin"
    if not shop_id:
        if is_admin:
            shop_id = ""
        else:
            assigned = _get_assigned_shop()
            shop_id = assigned.get("id", "") if assigned else ""

    all_data = get_all(COL_STOCK_OUT)
    data = []

    for r in sorted(all_data, key=lambda x: x.get("timestamp", ""), reverse=True):
        if shop_id and r.get("shop_id") != shop_id:
            continue
        ts = r.get("timestamp", "")
        if date_from and ts < date_from:
            continue
        if date_to and ts > date_to + " 23:59:59":
            continue
        data.append({
            "Transaction ID": r.get("id", ""),
            "Shop": r.get("shop_name", ""),
            "Product Name": r.get("product_name", ""),
            "Quantity Removed": str(r.get("qty", 0)),
            "Customer": r.get("customer", ""),
            "Reason": r.get("reason", ""),
            "Removed By": r.get("removed_by", ""),
            "Timestamp": ts,
        })
    headers = list(data[0].keys()) if data else []
    return render_template("reports_table.html", title="Stock Out Report", headers=headers, data=data, date_from=date_from, date_to=date_to, shops=shops_list, shop_id=shop_id)


@app.route("/users")
def users():
    users_data = get_all(COL_USERS)
    user_list = []
    for u in users_data:
        user_list.append({
            "id": u.get("id", ""),
            "full_name": u.get("full_name", ""),
            "username": u.get("username", ""),
            "role": u.get("role", ""),
            "date_created": u.get("date_created", ""),
        })
    return render_template("users.html", users=user_list)


@app.route("/users/add", methods=["POST"])
def add_user():
    if not validate_csrf():
        return redirect(url_for("users"))
    full_name = sanitize_html(request.form.get("full_name", ""))
    username = sanitize_html(request.form.get("username", ""))
    password = request.form.get("password", "")
    role = sanitize_html(request.form.get("role", "staff"))

    if not full_name or not username or not password:
        flash("All fields are required", "danger")
        return redirect(url_for("users"))

    existing = get_all(COL_USERS)
    for u in existing:
        if u.get("username") == username:
            flash("Username already exists", "danger")
            return redirect(url_for("users"))

    uid = generate_id("U", COL_USERS)
    hashed_pw = hash_password(password)
    date_created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    add_doc(COL_USERS, uid, {
        "full_name": full_name,
        "username": username,
        "password": hashed_pw,
        "role": role,
        "date_created": date_created,
    })
    flash(f"User '{full_name}' created!", "success")
    return redirect(url_for("users"))


@app.route("/users/edit", methods=["POST"])
def edit_user():
    if not validate_csrf():
        return redirect(url_for("users"))
    uid = sanitize_html(request.form.get("uid", ""))
    full_name = sanitize_html(request.form.get("full_name", ""))
    username = sanitize_html(request.form.get("username", ""))
    password = request.form.get("password", "")
    role = sanitize_html(request.form.get("role", "staff"))

    if not uid or not full_name or not username:
        flash("Required fields missing", "danger")
        return redirect(url_for("users"))

    db = safe_get_db()
    doc = db.collection(COL_USERS).document(uid).get()
    if not doc.exists:
        flash("User not found", "danger")
        return redirect(url_for("users"))

    existing_data = doc.to_dict()
    update_data = {
        "full_name": full_name,
        "username": username,
        "role": role,
    }
    if password:
        update_data["password"] = hash_password(password)
    update_doc(COL_USERS, uid, update_data)
    flash("User updated!", "success")
    return redirect(url_for("users"))


@app.route("/users/delete/<uid>")
def delete_user(uid):
    if uid == session.get("user_id"):
        flash("Cannot delete yourself!", "danger")
        return redirect(url_for("users"))

    db = safe_get_db()
    doc = db.collection(COL_USERS).document(uid).get()
    if doc.exists:
        delete_doc(COL_USERS, uid)
        flash("User deleted!", "success")
    else:
        flash("User not found", "danger")
    return redirect(url_for("users"))


@app.route("/seed-sample")
@login_required
def seed_sample():
    existing = get_all(COL_PRODUCTS)
    if existing:
        flash("Sample data already exists", "info")
        return redirect(url_for("products"))

    sample_products = [
        ("P001", "Rice 5kg", "Food", "Bag", "250", "300", 50, 10, "2024-01-15"),
        ("P002", "Cooking Oil 1L", "Food", "Bottle", "180", "220", 30, 8, "2024-01-15"),
        ("P003", "Sugar 1kg", "Food", "Pack", "80", "100", 20, 5, "2024-01-15"),
        ("P004", "Soap Bar", "Personal Care", "Piece", "15", "25", 100, 20, "2024-01-15"),
        ("P005", "Shampoo 200ml", "Personal Care", "Bottle", "120", "180", 15, 5, "2024-01-15"),
        ("P006", "Bread Loaf", "Food", "Piece", "30", "45", 8, 10, "2024-01-15"),
        ("P007", "Milk 1L", "Dairy", "Bottle", "55", "70", 25, 5, "2024-01-15"),
        ("P008", "Toothpaste", "Personal Care", "Tube", "60", "90", 40, 10, "2024-01-15"),
        ("P009", "Detergent 1kg", "Cleaning", "Pack", "150", "200", 12, 5, "2024-01-15"),
        ("P010", "Mineral Water 1L", "Beverages", "Bottle", "15", "25", 60, 15, "2024-01-15"),
    ]
    for pid, name, cat, unit, bp, sp, qty, reorder, date in sample_products:
        add_doc(COL_PRODUCTS, pid, {
            "name": name,
            "category": cat,
            "unit": unit,
            "buying_price": bp,
            "selling_price": sp,
            "quantity": qty,
            "reorder_level": reorder,
            "date_added": date,
        })
    flash("Sample products added!", "success")
    return redirect(url_for("products"))


def _get_assigned_shop():
    username = session.get("username", "")
    shops = get_all(COL_SHOPS)
    for s in shops:
        if f"({username})" in s.get("salesman", ""):
            return s
    return None


@app.route("/shops")
@login_required
def shops():
    all_data = get_all(COL_SHOPS)
    users_data = get_all(COL_USERS)
    is_admin = session.get("role") == "admin"

    if is_admin:
        shop_list = [
            {"id": s.get("id", ""), "name": s.get("name", ""), "location": s.get("location", ""),
             "salesman": s.get("salesman", ""), "date_created": s.get("date_created", "")}
            for s in all_data
        ]
    else:
        assigned = _get_assigned_shop()
        shop_list = [assigned] if assigned else []

    staff_list = [
        {"id": u.get("id", ""), "full_name": u.get("full_name", ""), "username": u.get("username", ""), "role": u.get("role", "")}
        for u in users_data
    ]
    return render_template("shops.html", shops=shop_list, staff=staff_list, assigned=_get_assigned_shop())


@app.route("/shops/<sid>")
@login_required
def shop_products(sid):
    if session.get("role") != "admin":
        assigned = _get_assigned_shop()
        if not assigned or assigned.get("id") != sid:
            flash("Access denied", "danger")
            return redirect(url_for("shops"))

    shops_data = get_all(COL_SHOPS)
    shop_name = ""
    for s in shops_data:
        if s.get("id") == sid:
            shop_name = s.get("name", "")
            break

    if not shop_name:
        flash("Shop not found", "danger")
        return redirect(url_for("shops"))

    main_products = get_all(COL_PRODUCTS)
    prices = {}
    warehouse_products = []
    for p in main_products:
        pid = p.get("id", "")
        price = float(p.get("selling_price", 0))
        prices[pid] = price
        qty = int(p.get("quantity", 0))
        warehouse_products.append({"id": pid, "name": p.get("name", ""), "quantity": qty, "price": price})

    stock_data = get_all(COL_SHOP_STOCK)
    products = {}
    for row in stock_data:
        if row.get("shop_id") == sid:
            pid = row.get("product_id", "")
            pname = row.get("product_name", "")
            qty = int(row.get("qty", 0))
            if pid in products:
                products[pid]["shop_qty"] += qty
            else:
                products[pid] = {"id": pid, "name": pname, "shop_qty": qty, "unit_price": prices.get(pid, 0)}

    product_list = sorted(products.values(), key=lambda x: x["name"])
    grand_total = sum(p["shop_qty"] * p["unit_price"] for p in product_list)

    records = sorted(
        [r for r in stock_data if r.get("shop_id") == sid],
        key=lambda x: x.get("timestamp", ""),
        reverse=True,
    )

    return render_template("shop_products.html", shop=shop_name, shop_id=sid, products=product_list, records=records, grand_total=grand_total, warehouse_products=warehouse_products)


@app.route("/shops/<sid>/stock-in", methods=["POST"])
def shop_stock_in(sid):
    if not validate_csrf():
        return redirect(url_for("shop_products", sid=sid))

    product_id = sanitize_html(request.form.get("product_id", ""))
    quantity = request.form.get("quantity", "0")

    if not product_id or not quantity:
        flash("Product and quantity are required", "danger")
        return redirect(url_for("shop_products", sid=sid))

    try:
        qty = int(quantity)
        if qty <= 0:
            flash("Quantity must be positive", "danger")
            return redirect(url_for("shop_products", sid=sid))
    except ValueError:
        flash("Invalid quantity", "danger")
        return redirect(url_for("shop_products", sid=sid))

    db = safe_get_db()
    doc = db.collection(COL_PRODUCTS).document(product_id).get()
    if not doc.exists:
        flash("Product not found in warehouse", "danger")
        return redirect(url_for("shop_products", sid=sid))

    product = doc.to_dict()
    product_name = product.get("name", "")
    current_qty = int(product.get("quantity", 0))

    if qty > current_qty:
        flash(f"Insufficient stock! Only {current_qty} {product_name} available in warehouse", "danger")
        return redirect(url_for("shop_products", sid=sid))

    new_qty = current_qty - qty
    update_doc(COL_PRODUCTS, product_id, {"quantity": new_qty})

    shops_data = get_all(COL_SHOPS)
    shop_name = ""
    for s in shops_data:
        if s.get("id") == sid:
            shop_name = s.get("name", "")
            break

    tid = generate_id("TR", COL_SHOP_STOCK)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    transferred_by = session.get("full_name", "Shop Staff")

    add_doc(COL_SHOP_STOCK, tid, {
        "shop_id": sid,
        "shop_name": shop_name,
        "product_id": product_id,
        "product_name": product_name,
        "qty": qty,
        "timestamp": timestamp,
        "transferred_by": transferred_by,
    })
    flash(f"Received {qty} {product_name} into {shop_name} from warehouse!", "success")
    return redirect(url_for("shop_products", sid=sid))


@app.route("/shops/add", methods=["POST"])
def add_shop():
    if not validate_csrf():
        return redirect(url_for("shops"))
    name = sanitize_html(request.form.get("name", ""))
    location = sanitize_html(request.form.get("location", ""))
    salesman = sanitize_html(request.form.get("salesman", ""))

    if not name:
        flash("Shop name is required", "danger")
        return redirect(url_for("shops"))

    sid = generate_id("S", COL_SHOPS)
    date_created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    add_doc(COL_SHOPS, sid, {
        "name": name,
        "location": location,
        "salesman": salesman,
        "date_created": date_created,
    })
    flash(f"Shop '{name}' added!", "success")
    return redirect(url_for("shops"))


@app.route("/shops/edit", methods=["POST"])
def edit_shop():
    if not validate_csrf():
        return redirect(url_for("shops"))
    sid = sanitize_html(request.form.get("sid", ""))
    name = sanitize_html(request.form.get("name", ""))
    location = sanitize_html(request.form.get("location", ""))
    salesman = sanitize_html(request.form.get("salesman", ""))

    if not sid or not name:
        flash("Shop ID and name are required", "danger")
        return redirect(url_for("shops"))

    db = safe_get_db()
    doc = db.collection(COL_SHOPS).document(sid).get()
    if doc.exists:
        update_doc(COL_SHOPS, sid, {
            "name": name,
            "location": location,
            "salesman": salesman,
        })
        flash(f"Shop '{name}' updated!", "success")
    else:
        flash("Shop not found", "danger")
    return redirect(url_for("shops"))


@app.route("/shops/delete/<sid>")
def delete_shop(sid):
    db = safe_get_db()
    doc = db.collection(COL_SHOPS).document(sid).get()
    if doc.exists:
        delete_doc(COL_SHOPS, sid)
        flash("Shop deleted!", "success")
    else:
        flash("Shop not found", "danger")
    return redirect(url_for("shops"))


@app.route("/distribute")
@login_required
def distribute():
    shops_data = get_all(COL_SHOPS)
    products_data = get_all(COL_PRODUCTS)
    stock_data = get_all(COL_SHOP_STOCK)

    shop_list = [
        {"id": s.get("id", ""), "name": s.get("name", ""), "location": s.get("location", ""), "salesman": s.get("salesman", "")}
        for s in shops_data
    ]

    product_list = [
        {"id": p.get("id", ""), "name": p.get("name", ""), "quantity": p.get("quantity", 0)}
        for p in products_data
    ]

    records = sorted(
        [r for r in stock_data if r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )

    return render_template("distribute.html", shops=shop_list, products=product_list, records=records)


@app.route("/distribute/transfer", methods=["POST"])
@login_required
def transfer_stock():
    if not validate_csrf():
        return redirect(url_for("distribute"))
    shop_id = sanitize_html(request.form.get("shop_id", ""))
    product_id = sanitize_html(request.form.get("product_id", ""))
    quantity = request.form.get("quantity", "0")

    if not shop_id or not product_id or not quantity:
        flash("Shop, product, and quantity are required", "danger")
        return redirect(url_for("distribute"))

    try:
        qty = int(quantity)
        if qty <= 0:
            flash("Quantity must be positive", "danger")
            return redirect(url_for("distribute"))
    except ValueError:
        flash("Invalid quantity", "danger")
        return redirect(url_for("distribute"))

    db = safe_get_db()

    doc = db.collection(COL_PRODUCTS).document(product_id).get()
    if not doc.exists:
        flash("Product not found", "danger")
        return redirect(url_for("distribute"))

    product = doc.to_dict()
    product_name = product.get("name", "")
    current_qty = int(product.get("quantity", 0))

    if qty > current_qty:
        flash(f"Insufficient stock! Only {current_qty} {product_name} available", "danger")
        return redirect(url_for("distribute"))

    new_qty = current_qty - qty
    update_doc(COL_PRODUCTS, product_id, {"quantity": new_qty})

    shops_data = get_all(COL_SHOPS)
    shop_name = ""
    for s in shops_data:
        if s.get("id") == shop_id:
            shop_name = s.get("name", "")
            break

    tid = generate_id("TR", COL_SHOP_STOCK)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    transferred_by = session.get("full_name", "Staff")

    add_doc(COL_SHOP_STOCK, tid, {
        "shop_id": shop_id,
        "shop_name": shop_name,
        "product_id": product_id,
        "product_name": product_name,
        "qty": qty,
        "timestamp": timestamp,
        "transferred_by": transferred_by,
    })
    flash(f"{qty} {product_name} transferred to {shop_name}!", "success")
    return redirect(url_for("distribute"))


@app.route("/pos")
@login_required
def pos():
    shops_data = get_all(COL_SHOPS)
    is_admin = session.get("role") == "admin"

    if is_admin:
        shop_list = [{"id": s.get("id", ""), "name": s.get("name", "")} for s in shops_data]
        selected_shop_id = request.args.get("shop", "")
    else:
        assigned = _get_assigned_shop()
        selected_shop_id = assigned.get("id", "") if assigned else ""
        shop_list = [{"id": selected_shop_id, "name": assigned.get("name", "")}] if assigned else []

    products = []
    stock_data = get_all(COL_SHOP_STOCK)
    main_products = get_all(COL_PRODUCTS)
    prices = {p.get("id", ""): float(p.get("selling_price", 0)) for p in main_products}

    stock_in_shop = {}
    for row in stock_data:
        if row.get("shop_id") == selected_shop_id:
            pid = row.get("product_id", "")
            qty = int(row.get("qty", 0))
            stock_in_shop[pid] = stock_in_shop.get(pid, 0) + qty

    for p in main_products:
        pid = p.get("id", "")
        sqty = stock_in_shop.get(pid, 0)
        if sqty > 0:
            products.append({
                "id": pid,
                "name": p.get("name", ""),
                "price": prices.get(pid, 0),
                "qty": sqty,
                "unit": p.get("unit", ""),
            })

    records = get_all(COL_SALES)
    sales = sorted(
        [r for r in records if r.get("shop_id") == selected_shop_id and r.get("timestamp")],
        key=lambda x: x["timestamp"],
        reverse=True,
    )[:20]

    return render_template("pos.html", shops=shop_list, products=products, sales=sales, selected_shop=selected_shop_id, is_admin=is_admin)


@app.route("/pos/sell", methods=["POST"])
@login_required
def pos_sell():
    if not validate_csrf():
        return redirect(url_for("pos"))

    shop_id = sanitize_html(request.form.get("shop_id", ""))
    items_json = request.form.get("items", "[]")

    if not shop_id or not items_json:
        flash("Shop and items are required", "danger")
        return redirect(url_for("pos"))

    try:
        items = json.loads(items_json)
        if not items:
            flash("No items in cart", "danger")
            return redirect(url_for("pos"))
    except (json.JSONDecodeError, TypeError):
        flash("Invalid items data", "danger")
        return redirect(url_for("pos"))

    shops_data = get_all(COL_SHOPS)
    shop_name = ""
    for s in shops_data:
        if s.get("id") == shop_id:
            shop_name = s.get("name", "")
            break

    if not shop_name:
        flash("Shop not found", "danger")
        return redirect(url_for("pos"))

    stock_data = get_all(COL_SHOP_STOCK)
    current_stock = {}
    for row in stock_data:
        if row.get("shop_id") == shop_id:
            pid = row.get("product_id", "")
            qty = int(row.get("qty", 0))
            current_stock[pid] = current_stock.get(pid, 0) + qty

    db = safe_get_db()
    grand_total = 0
    receipt_items = []

    for item in items:
        pid = item.get("product_id", "")
        qty = int(item.get("qty", 0))
        price = float(item.get("price", 0))

        if not pid or qty <= 0:
            continue
        if current_stock.get(pid, 0) < qty:
            flash(f"Insufficient stock for '{item.get('name', pid)}'", "danger")
            return redirect(url_for("pos"))

        doc = db.collection(COL_PRODUCTS).document(pid).get()
        product_name = doc.to_dict().get("name", pid) if doc.exists else pid

        total = qty * price
        grand_total += total
        receipt_items.append({"name": product_name, "qty": qty, "price": price, "total": total})

        tid = generate_id("SL", COL_SHOP_STOCK)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        add_doc(COL_SHOP_STOCK, tid, {
            "shop_id": shop_id,
            "shop_name": shop_name,
            "product_id": pid,
            "product_name": product_name,
            "qty": -qty,
            "timestamp": timestamp,
            "transferred_by": session.get("full_name", "Staff"),
            "type": "sale",
        })

        sid = generate_id("SO", COL_STOCK_OUT)
        add_doc(COL_STOCK_OUT, sid, {
            "product_id": pid,
            "product_name": product_name,
            "qty": qty,
            "reason": "pos_sale",
            "shop_id": shop_id,
            "shop_name": shop_name,
            "customer": sanitize_html(request.form.get("customer", "")),
            "removed_by": session.get("full_name", "Staff"),
            "timestamp": timestamp,
        })

    receipt_id = generate_id("R", COL_SALES)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sold_by = session.get("full_name", "Staff")
    add_doc(COL_SALES, receipt_id, {
        "receipt_id": receipt_id,
        "shop_id": shop_id,
        "shop_name": shop_name,
        "items": receipt_items,
        "grand_total": grand_total,
        "customer": sanitize_html(request.form.get("customer", "")),
        "sold_by": sold_by,
        "timestamp": timestamp,
    })

    flash(f"Sale completed! Receipt #{receipt_id} — Total: MK{grand_total:.2f}", "success")
    return redirect(url_for("pos"))


if __name__ == "__main__":
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
