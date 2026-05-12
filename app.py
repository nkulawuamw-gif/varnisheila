import os
import json
import hashlib
import secrets
import logging
from datetime import datetime, date
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

import firebase_admin
from firebase_admin import credentials, firestore


# =========================
# APP CONFIG
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.debug = os.environ.get("DEBUG", "False") == "True"


# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =========================
# FIREBASE INIT
# =========================
_firebase_db = None
_firebase_initialized = False


def init_firebase():
    global _firebase_db, _firebase_initialized

    if _firebase_initialized:
        return _firebase_db

    try:
        creds = None
        json_str = os.environ.get("FIREBASE_SERVICE_ACCOUNT") or os.environ.get("FIREBASE_CREDENTIALS_JSON")
        if json_str:
            creds = json.loads(json_str)

        if not creds:
            for path in [
                os.environ.get("FIREBASE_CREDENTIALS", ""),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "private", "firebase-key.json"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "private", "credentials.json"),
            ]:
                if path and os.path.exists(path):
                    with open(path) as f:
                        creds = json.load(f)
                    break

        if not creds:
            raise Exception("No Firebase credentials. Set FIREBASE_SERVICE_ACCOUNT env var or place private/firebase-key.json")

        if not firebase_admin._apps:
            firebase_admin.initialize_app(credentials.Certificate(creds))

        _firebase_db = firestore.client()
        _firebase_initialized = True
        logger.info("Firebase initialized")

    except Exception as e:
        logger.error(f"Firebase init failed: {e}")
        _firebase_db = None

    return _firebase_db


def get_db():
    return init_firebase()


def safe_get_db():
    db = get_db()
    if db is None:
        raise Exception("Firebase not initialized")
    return db


# =========================
# COLLECTIONS
# =========================
COL_PRODUCTS = "products"
COL_STOCK_IN = "stock_in"
COL_STOCK_OUT = "stock_out"
COL_USERS = "users"
COL_SHOPS = "shops"
COL_SHOP_STOCK = "shop_stock"
COL_SALES = "sales"
COL_TRANSFERS = "transfers"


# =========================
# HELPERS
# =========================
def get_all(collection):
    db = safe_get_db()
    try:
        docs = db.collection(collection).stream()
        result = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            result.append(data)
        return result
    except Exception as e:
        logger.error(f"get_all({collection}): {e}")
        return []


def get_doc(collection, doc_id):
    db = safe_get_db()
    try:
        doc = db.collection(collection).document(doc_id).get()
        if doc.exists:
            data = doc.to_dict()
            data["id"] = doc.id
            return data
    except Exception as e:
        logger.error(f"get_doc({collection}, {doc_id}): {e}")
    return None


def add_doc(collection, doc_id, data):
    db = safe_get_db()
    db.collection(collection).document(doc_id).set(data)


def update_doc(collection, doc_id, data):
    db = safe_get_db()
    db.collection(collection).document(doc_id).update(data)


def delete_doc(collection, doc_id):
    db = safe_get_db()
    db.collection(collection).document(doc_id).delete()


def generate_id(prefix, collection):
    docs = get_all(collection)
    max_num = 0
    for d in docs:
        if d["id"].startswith(prefix):
            try:
                num = int(d["id"].replace(prefix, ""))
                max_num = max(max_num, num)
            except:
                pass
    return f"{prefix}{max_num+1:03d}"


def get_product_name(pid):
    p = get_doc(COL_PRODUCTS, pid)
    return p["name"] if p else pid


def get_shop_name(sid):
    s = get_doc(COL_SHOPS, sid)
    return s["name"] if s else sid


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return date.today().isoformat()


# =========================
# SECURITY HELPERS
# =========================
def sanitize(text):
    return bleach.clean(text, strip=True) if text else ""


def hash_password(password):
    salt = secrets.token_hex(16)
    return salt + "$" + hashlib.sha256((salt + password).encode()).hexdigest()


def check_password(password, hashed):
    try:
        salt, h = hashed.split("$")
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except:
        return False


# =========================
# AUTH DECORATORS
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


# =========================
# CONTEXT PROCESSOR
# =========================
@app.context_processor
def inject_globals():
    ctx = {
        "current_user": session.get("username", ""),
        "shops_list": [],
    }
    try:
        ctx["shops_list"] = get_all(COL_SHOPS)
        if "user_id" in session:
            user = get_doc(COL_USERS, session["user_id"])
            if user:
                session["username"] = user.get("full_name", user.get("username", ""))
    except:
        pass
    return ctx


# =========================
# AUTH ROUTES
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize(request.form.get("username", ""))
        password = request.form.get("password", "")

        for u in get_all(COL_USERS):
            if u["username"] == username and check_password(password, u.get("password", "")):
                session["user_id"] = u["id"]
                session["role"] = u.get("role", "staff")
                session["username"] = u.get("full_name", u["username"])
                return redirect("/dashboard")

        flash("Invalid username or password", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# DASHBOARD
# =========================
@app.route("/")
def index():
    return redirect("/dashboard")


@app.route("/dashboard")
@login_required
def dashboard():
    products = get_all(COL_PRODUCTS)
    total_products = len(products)
    total_qty = sum(p.get("quantity", 0) for p in products)
    low_stock_count = sum(1 for p in products if p.get("quantity", 0) <= p.get("reorder_level", 0))

    si = get_all(COL_STOCK_IN)
    si.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    so = get_all(COL_STOCK_OUT)
    so.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return render_template("dashboard.html",
        total_products=total_products,
        total_qty=total_qty,
        low_stock_count=low_stock_count,
        recent_in=si[:5],
        recent_out=so[:5],
    )


# =========================
# PRODUCTS
# =========================
@app.route("/products")
@login_required
def products():
    search = request.args.get("search", "").strip().lower()
    all_products = get_all(COL_PRODUCTS)
    if search:
        all_products = [p for p in all_products if search in p.get("name", "").lower() or search in p.get("category", "").lower()]
    for p in all_products:
        p["low_stock"] = p.get("quantity", 0) <= p.get("reorder_level", 0)
    return render_template("products.html", products=all_products, search=search)


@app.route("/products/add", methods=["POST"])
@login_required
def add_product():
    name = sanitize(request.form.get("name", ""))
    if not name:
        flash("Product name is required", "danger")
        return redirect("/products")

    add_doc(COL_PRODUCTS, generate_id("P", COL_PRODUCTS), {
        "name": name,
        "category": sanitize(request.form.get("category", "")),
        "unit": sanitize(request.form.get("unit", "pcs")),
        "buying_price": float(request.form.get("buying_price", 0)),
        "selling_price": float(request.form.get("selling_price", 0)),
        "quantity": int(request.form.get("quantity", 0)),
        "reorder_level": int(request.form.get("reorder_level", 0)),
    })
    flash(f"Product '{name}' added", "success")
    return redirect("/products")


@app.route("/products/edit", methods=["POST"])
@login_required
def edit_product():
    pid = request.form.get("pid")
    if not pid:
        flash("Product ID required", "danger")
        return redirect("/products")

    update_doc(COL_PRODUCTS, pid, {
        "name": sanitize(request.form.get("name", "")),
        "category": sanitize(request.form.get("category", "")),
        "unit": sanitize(request.form.get("unit", "pcs")),
        "buying_price": float(request.form.get("buying_price", 0)),
        "selling_price": float(request.form.get("selling_price", 0)),
        "quantity": int(request.form.get("quantity", 0)),
        "reorder_level": int(request.form.get("reorder_level", 0)),
    })
    flash("Product updated", "success")
    return redirect("/products")


@app.route("/products/delete/<pid>")
@login_required
def delete_product(pid):
    name = get_product_name(pid)
    delete_doc(COL_PRODUCTS, pid)
    flash(f"Product '{name}' deleted", "warning")
    return redirect("/products")


# =========================
# STOCK IN
# =========================
@app.route("/stock-in")
@login_required
def stock_in():
    records = get_all(COL_STOCK_IN)
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template("stock_in.html", products=get_all(COL_PRODUCTS), records=records)


@app.route("/stock-in/add", methods=["POST"])
@login_required
def add_stock_in():
    product_id = request.form.get("product_id", "")
    qty = int(request.form.get("quantity", 0))

    if not product_id or qty <= 0:
        flash("Invalid product or quantity", "danger")
        return redirect("/stock-in")

    product = get_doc(COL_PRODUCTS, product_id)
    if not product:
        flash("Product not found", "danger")
        return redirect("/stock-in")

    update_doc(COL_PRODUCTS, product_id, {"quantity": product.get("quantity", 0) + qty})

    add_doc(COL_STOCK_IN, generate_id("SI", COL_STOCK_IN), {
        "product_id": product_id,
        "product_name": product["name"],
        "qty": qty,
        "supplier": sanitize(request.form.get("supplier", "")),
        "purchase_date": request.form.get("purchase_date", today_str()),
        "added_by": session.get("username", ""),
        "timestamp": now_str(),
    })
    flash(f"Added {qty} x {product['name']}", "success")
    return redirect("/stock-in")


# =========================
# STOCK OUT
# =========================
@app.route("/stock-out")
@login_required
def stock_out():
    records = get_all(COL_STOCK_OUT)
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template("stock_out.html", products=get_all(COL_PRODUCTS), records=records)


@app.route("/stock-out/add", methods=["POST"])
@login_required
def add_stock_out():
    product_id = request.form.get("product_id", "")
    qty = int(request.form.get("quantity", 0))

    if not product_id or qty <= 0:
        flash("Invalid product or quantity", "danger")
        return redirect("/stock-out")

    product = get_doc(COL_PRODUCTS, product_id)
    if not product:
        flash("Product not found", "danger")
        return redirect("/stock-out")

    current_qty = product.get("quantity", 0)
    if qty > current_qty:
        flash(f"Not enough stock. Only {current_qty} available.", "danger")
        return redirect("/stock-out")

    update_doc(COL_PRODUCTS, product_id, {"quantity": current_qty - qty})

    add_doc(COL_STOCK_OUT, generate_id("SO", COL_STOCK_OUT), {
        "product_id": product_id,
        "product_name": product["name"],
        "qty": qty,
        "customer": sanitize(request.form.get("customer", "")),
        "reason": request.form.get("reason", "sale"),
        "removed_by": session.get("username", ""),
        "timestamp": now_str(),
    })
    flash(f"Removed {qty} x {product['name']}", "success")
    return redirect("/stock-out")


# =========================
# LOW STOCK
# =========================
@app.route("/low-stock")
@login_required
def low_stock():
    products = get_all(COL_PRODUCTS)
    items = [p for p in products if p.get("quantity", 0) <= p.get("reorder_level", 0)]
    return render_template("low_stock.html", items=items)


# =========================
# POINT OF SALE
# =========================
@app.route("/pos")
@login_required
def pos():
    shop_id = request.args.get("shop", "")
    shops = get_all(COL_SHOPS)
    is_admin = session.get("role") == "admin"
    user_shop_id = None

    if not is_admin:
        username = session.get("username", "")
        for s in shops:
            if username and username in (s.get("salesman") or ""):
                user_shop_id = s.id
                break

    selected_shop = shop_id or user_shop_id or ""
    is_auto_selected = bool(not shop_id and user_shop_id)
    selected_shop_name = ""
    products = []
    sales = []

    if selected_shop:
        s = get_doc(COL_SHOPS, selected_shop)
        selected_shop_name = s["name"] if s else ""

        for sk in get_all(COL_SHOP_STOCK):
            if sk.get("shop_id") != selected_shop:
                continue
            prod = get_doc(COL_PRODUCTS, sk.get("product_id"))
            if prod:
                products.append({
                    "id": sk.get("product_id"),
                    "name": prod.get("name", ""),
                    "price": sk.get("price", prod.get("selling_price", 0)),
                    "qty": sk.get("qty", 0),
                    "unit": prod.get("unit", "pcs"),
                })

        all_sales = get_all(COL_SALES)
        shop_sales = [s for s in all_sales if s.get("shop_id") == selected_shop]
        shop_sales.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        sales = shop_sales[:5]

    return render_template("pos.html",
        shops=shops,
        selected_shop=selected_shop,
        selected_shop_name=selected_shop_name,
        products=products,
        sales=sales,
        is_admin=is_admin,
        is_auto_selected=is_auto_selected,
    )


@app.route("/pos/sell", methods=["POST"])
@login_required
def pos_sell():
    shop_id = request.form.get("shop_id", "")
    items_json = request.form.get("items", "[]")
    customer = sanitize(request.form.get("customer", "Walk-in Customer"))

    try:
        items = json.loads(items_json)
    except:
        flash("Invalid items data", "danger")
        return redirect("/pos" + (f"?shop={shop_id}" if shop_id else ""))

    if not items:
        flash("Cart is empty", "warning")
        return redirect("/pos" + (f"?shop={shop_id}" if shop_id else ""))

    grand_total = 0
    for item in items:
        grand_total += item.get("price", 0) * item.get("qty", 0)

        for sk in get_all(COL_SHOP_STOCK):
            if sk.get("shop_id") == shop_id and sk.get("product_id") == item["product_id"]:
                new_qty = sk.get("qty", 0) - item["qty"]
                if new_qty < 0:
                    flash(f"Not enough {item.get('name', 'product')}", "danger")
                    return redirect("/pos" + (f"?shop={shop_id}" if shop_id else ""))
                update_doc(COL_SHOP_STOCK, sk["id"], {"qty": new_qty})
                break

    receipt_id = generate_id("R", COL_SALES)
    add_doc(COL_SALES, receipt_id, {
        "receipt_id": receipt_id,
        "shop_id": shop_id,
        "shop_name": get_shop_name(shop_id),
        "items": items,
        "grand_total": grand_total,
        "customer": customer,
        "sold_by": session.get("username", ""),
        "timestamp": now_str(),
    })

    flash(f"Sale complete! Receipt: {receipt_id} Total: MK{grand_total:.2f}", "success")
    return redirect("/pos" + (f"?shop={shop_id}" if shop_id else ""))


# =========================
# SHOPS
# =========================
@app.route("/shops")
@login_required
def shops():
    return render_template("shops.html", shops=get_all(COL_SHOPS), staff=get_all(COL_USERS))


@app.route("/shops/add", methods=["POST"])
@login_required
def add_shop():
    name = sanitize(request.form.get("name", ""))
    if not name:
        flash("Shop name is required", "danger")
        return redirect("/shops")

    add_doc(COL_SHOPS, generate_id("S", COL_SHOPS), {
        "name": name,
        "location": sanitize(request.form.get("location", "")),
        "salesman": sanitize(request.form.get("salesman", "")),
        "date_created": today_str(),
    })
    flash(f"Shop '{name}' created", "success")
    return redirect("/shops")


@app.route("/shops/edit", methods=["POST"])
@login_required
def edit_shop():
    sid = request.form.get("sid")
    name = sanitize(request.form.get("name", ""))
    if not sid or not name:
        flash("Invalid shop data", "danger")
        return redirect("/shops")

    update_doc(COL_SHOPS, sid, {
        "name": name,
        "location": sanitize(request.form.get("location", "")),
        "salesman": sanitize(request.form.get("salesman", "")),
    })
    flash(f"Shop '{name}' updated", "success")
    return redirect("/shops")


@app.route("/shops/delete/<sid>")
@login_required
def delete_shop(sid):
    name = get_shop_name(sid)
    delete_doc(COL_SHOPS, sid)
    flash(f"Shop '{name}' deleted", "warning")
    return redirect("/shops")


# =========================
# SHOP PRODUCTS / WAREHOUSE TRANSFER
# =========================
@app.route("/shops/<sid>")
@login_required
def shop_products(sid):
    shop = get_doc(COL_SHOPS, sid)
    if not shop:
        flash("Shop not found", "danger")
        return redirect("/shops")

    warehouse_products = get_all(COL_PRODUCTS)
    for p in warehouse_products:
        p["price"] = p.get("selling_price", 0)

    products = []
    grand_total = 0
    for sk in get_all(COL_SHOP_STOCK):
        if sk.get("shop_id") != sid:
            continue
        prod = get_doc(COL_PRODUCTS, sk.get("product_id"))
        if prod:
            unit_price = sk.get("price", prod.get("selling_price", 0))
            qty = sk.get("qty", 0)
            products.append({
                "id": sk.get("product_id"),
                "name": prod.get("name", ""),
                "shop_qty": qty,
                "unit_price": unit_price,
            })
            grand_total += qty * unit_price

    trans = [t for t in get_all(COL_TRANSFERS) if t.get("shop_id") == sid]
    trans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return render_template("shop_products.html",
        shop=shop["name"],
        shop_id=sid,
        warehouse_products=warehouse_products,
        products=products,
        grand_total=grand_total,
        records=trans,
    )


def _transfer_to_shop(shop_id, product_id, qty, transferred_by):
    product = get_doc(COL_PRODUCTS, product_id)
    if not product:
        return False, "Product not found"

    warehouse_qty = product.get("quantity", 0)
    if qty > warehouse_qty:
        return False, f"Not enough in warehouse. Only {warehouse_qty} available."

    update_doc(COL_PRODUCTS, product_id, {"quantity": warehouse_qty - qty})

    found = None
    for sk in get_all(COL_SHOP_STOCK):
        if sk.get("shop_id") == shop_id and sk.get("product_id") == product_id:
            found = sk
            break

    if found:
        update_doc(COL_SHOP_STOCK, found["id"], {
            "qty": found.get("qty", 0) + qty,
            "price": product.get("selling_price", 0),
        })
    else:
        add_doc(COL_SHOP_STOCK, generate_id("SS", COL_SHOP_STOCK), {
            "shop_id": shop_id,
            "product_id": product_id,
            "qty": qty,
            "price": product.get("selling_price", 0),
        })

    add_doc(COL_TRANSFERS, generate_id("TF", COL_TRANSFERS), {
        "shop_id": shop_id,
        "shop_name": get_shop_name(shop_id),
        "product_id": product_id,
        "product_name": product["name"],
        "qty": qty,
        "transferred_by": transferred_by,
        "timestamp": now_str(),
    })

    return True, f"Transferred {qty} x {product['name']}"


@app.route("/shops/<sid>/stock-in", methods=["POST"])
@login_required
def shop_stock_in(sid):
    product_id = request.form.get("product_id", "")
    qty = int(request.form.get("quantity", 0))

    if not product_id or qty <= 0:
        flash("Invalid product or quantity", "danger")
        return redirect(url_for("shop_products", sid=sid))

    ok, msg = _transfer_to_shop(sid, product_id, qty, session.get("username", ""))
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("shop_products", sid=sid))


# =========================
# DISTRIBUTE
# =========================
@app.route("/distribute")
@login_required
def distribute():
    records = get_all(COL_TRANSFERS)
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return render_template("distribute.html",
        shops=get_all(COL_SHOPS),
        products=get_all(COL_PRODUCTS),
        records=records,
    )


@app.route("/distribute/transfer", methods=["POST"])
@login_required
def transfer_stock():
    shop_id = request.form.get("shop_id", "")
    product_id = request.form.get("product_id", "")
    qty = int(request.form.get("quantity", 0))

    if not shop_id or not product_id or qty <= 0:
        flash("Invalid transfer data", "danger")
        return redirect("/distribute")

    ok, msg = _transfer_to_shop(shop_id, product_id, qty, session.get("username", ""))
    flash(msg, "success" if ok else "danger")
    return redirect("/distribute")


# =========================
# USERS
# =========================
@app.route("/users")
@login_required
def users():
    return render_template("users.html", users=get_all(COL_USERS))


@app.route("/users/add", methods=["POST"])
@login_required
def add_user():
    full_name = sanitize(request.form.get("full_name", ""))
    username = sanitize(request.form.get("username", ""))
    password = request.form.get("password", "")
    role = request.form.get("role", "staff")

    if not full_name or not username or not password:
        flash("All fields required", "danger")
        return redirect("/users")

    for u in get_all(COL_USERS):
        if u["username"] == username:
            flash("Username already exists", "danger")
            return redirect("/users")

    add_doc(COL_USERS, generate_id("U", COL_USERS), {
        "full_name": full_name,
        "username": username,
        "password": hash_password(password),
        "role": role,
        "date_created": today_str(),
    })
    flash(f"User '{full_name}' created", "success")
    return redirect("/users")


@app.route("/users/edit", methods=["POST"])
@login_required
def edit_user():
    uid = request.form.get("uid")
    full_name = sanitize(request.form.get("full_name", ""))
    username = sanitize(request.form.get("username", ""))
    password = request.form.get("password", "")
    role = request.form.get("role", "staff")

    if not uid or not full_name or not username:
        flash("Invalid user data", "danger")
        return redirect("/users")

    data = {"full_name": full_name, "username": username, "role": role}
    if password:
        data["password"] = hash_password(password)

    update_doc(COL_USERS, uid, data)
    flash("User updated", "success")
    return redirect("/users")


@app.route("/users/delete/<uid>")
@login_required
def delete_user(uid):
    if uid == session.get("user_id"):
        flash("Cannot delete yourself", "danger")
        return redirect("/users")

    u = get_doc(COL_USERS, uid)
    name = u.get("full_name", uid) if u else uid
    delete_doc(COL_USERS, uid)
    flash(f"User '{name}' deleted", "warning")
    return redirect("/users")


# =========================
# REPORTS
# =========================
@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")


def _report_data(title, headers, rows, date_from="", date_to="", show_shop_filter=False):
    return render_template("reports_table.html",
        title=title,
        headers=headers,
        data=rows,
        date_from=date_from,
        date_to=date_to,
        shops=get_all(COL_SHOPS) if show_shop_filter else [],
    )


@app.route("/reports/stock")
@login_required
def report_stock():
    headers = ["ID", "Name", "Category", "Unit", "Buying Price", "Selling Price", "Quantity", "Reorder Level"]
    data = [{
        "ID": p.get("id", ""),
        "Name": p.get("name", ""),
        "Category": p.get("category", ""),
        "Unit": p.get("unit", ""),
        "Buying Price": p.get("buying_price", 0),
        "Selling Price": p.get("selling_price", 0),
        "Quantity": p.get("quantity", 0),
        "Reorder Level": p.get("reorder_level", 0),
    } for p in get_all(COL_PRODUCTS)]
    return _report_data("Stock Report", headers, data)


@app.route("/reports/low-stock")
@login_required
def report_low_stock():
    items = [p for p in get_all(COL_PRODUCTS) if p.get("quantity", 0) <= p.get("reorder_level", 0)]
    headers = ["ID", "Name", "Category", "Quantity", "Reorder Level"]
    data = [{
        "ID": p.get("id", ""),
        "Name": p.get("name", ""),
        "Category": p.get("category", ""),
        "Quantity": p.get("quantity", 0),
        "Reorder Level": p.get("reorder_level", 0),
    } for p in items]
    return _report_data("Low Stock Report", headers, data)


@app.route("/reports/stock-in")
@login_required
def report_stock_in():
    records = get_all(COL_STOCK_IN)
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    filtered = []
    for r in records:
        ts = r.get("timestamp", "")[:10]
        if date_from and ts < date_from:
            continue
        if date_to and ts > date_to:
            continue
        filtered.append(r)

    headers = ["Transaction ID", "Product", "Quantity", "Supplier", "Purchase Date", "Added By", "Timestamp"]
    data = [{
        "Transaction ID": r.get("id", ""),
        "Product": r.get("product_name", ""),
        "Quantity": r.get("qty", 0),
        "Supplier": r.get("supplier", ""),
        "Purchase Date": r.get("purchase_date", ""),
        "Added By": r.get("added_by", ""),
        "Timestamp": r.get("timestamp", ""),
    } for r in filtered]

    return _report_data("Stock In Report", headers, data, date_from, date_to, show_shop_filter=True)


@app.route("/reports/stock-out")
@login_required
def report_stock_out():
    records = get_all(COL_STOCK_OUT)
    records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    filtered = []
    for r in records:
        ts = r.get("timestamp", "")[:10]
        if date_from and ts < date_from:
            continue
        if date_to and ts > date_to:
            continue
        filtered.append(r)

    headers = ["Transaction ID", "Product", "Quantity", "Customer", "Reason", "Removed By", "Timestamp"]
    data = [{
        "Transaction ID": r.get("id", ""),
        "Product": r.get("product_name", ""),
        "Quantity": r.get("qty", 0),
        "Customer": r.get("customer", ""),
        "Reason": r.get("reason", ""),
        "Removed By": r.get("removed_by", ""),
        "Timestamp": r.get("timestamp", ""),
    } for r in filtered]

    return _report_data("Stock Out Report", headers, data, date_from, date_to, show_shop_filter=True)


# =========================
# SEED SAMPLE DATA
# =========================
@app.route("/seed-sample")
@login_required
def seed_sample():
    sample_products = [
        ("P001", "Maize Flour", "Food", "kg", 1500, 2200, 100, 20),
        ("P002", "Cooking Oil", "Food", "litre", 2500, 3500, 50, 10),
        ("P003", "Sugar", "Food", "kg", 1800, 2600, 80, 15),
        ("P004", "Rice", "Food", "kg", 2000, 3000, 60, 10),
        ("P005", "Salt", "Food", "kg", 500, 800, 200, 30),
        ("P006", "Soap", "Hygiene", "pcs", 800, 1200, 150, 20),
        ("P007", "Bottled Water", "Beverages", "bottle", 300, 500, 300, 50),
        ("P008", "Soft Drink", "Beverages", "bottle", 600, 1000, 200, 30),
        ("P009", "Bread", "Food", "loaf", 1200, 1800, 40, 10),
        ("P010", "Tea Leaves", "Beverages", "pkt", 400, 700, 100, 15),
    ]

    for pid, name, cat, unit, bp, sp, qty, rl in sample_products:
        if not get_doc(COL_PRODUCTS, pid):
            add_doc(COL_PRODUCTS, pid, {
                "name": name, "category": cat, "unit": unit,
                "buying_price": bp, "selling_price": sp,
                "quantity": qty, "reorder_level": rl,
            })

    for sid, name, loc, salesman in [
        ("S001", "City Centre Branch", "City Centre", "John Doe (john)"),
        ("S002", "Township Branch", "Township", "Jane Doe (jane)"),
    ]:
        if not get_doc(COL_SHOPS, sid):
            add_doc(COL_SHOPS, sid, {
                "name": name, "location": loc, "salesman": salesman, "date_created": today_str(),
            })

    if not any(u.get("username") == "admin" for u in get_all(COL_USERS)):
        add_doc(COL_USERS, "U001", {
            "full_name": "System Admin", "username": "admin",
            "password": hash_password("admin123"),
            "role": "admin", "date_created": today_str(),
        })

    flash("Sample data loaded! Login: admin / admin123", "success")
    return redirect("/dashboard")


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
