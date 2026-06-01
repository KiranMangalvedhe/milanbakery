"""
Milan Bakery Management System
Flask + Neon PostgreSQL + Vercel
Entry point for Vercel serverless deployment
"""

import os
import sys

# Add parent directory to path for template/static discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, g
)
import psycopg2
import psycopg2.extras
import psycopg2.pool
import bcrypt
from datetime import datetime, date
from functools import wraps
from dotenv import load_dotenv
from decimal import Decimal
import json

load_dotenv()


# ─────────────────────────────────────────────
# Type Conversion Helpers
# ─────────────────────────────────────────────
class DecimalEncoder(json.JSONEncoder):
    """Convert Decimal to float for JSON serialization."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def convert_decimals(obj):
    """Recursively convert Decimal to float in dict/list structures."""
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimals(item) for item in obj]
    elif isinstance(obj, Decimal):
        return float(obj)
    return obj

# ─────────────────────────────────────────────
# Flask App Setup
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", "milan-bakery-secret-dev-key-2025")
app.json_encoder = DecimalEncoder

# ─────────────────────────────────────────────
# Database Connection Pool
# ─────────────────────────────────────────────
_db_pool = None

def get_pool():
    global _db_pool
    if _db_pool is None:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL not set")
        _db_pool = psycopg2.pool.ThreadedConnectionPool(
            1, 10, db_url,
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    return _db_pool


def get_db():
    """Return the per-request DB connection from the pool."""
    if "db" not in g:
        g.db = get_pool().getconn()
        g.db.autocommit = False
    return g.db


@app.teardown_appcontext
def close_db(error):
    """Return the connection back to the pool after each request, always clean."""
    db = g.pop("db", None)
    if db is not None:
        try:
            db.rollback()  # reset any open/failed transaction before returning to pool
        except Exception:
            pass
        get_pool().putconn(db)


def query_db(sql, args=(), one=False, commit=False):
    """Execute a SELECT and return results (reuses per-request connection)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(sql, args)
        if commit:
            conn.commit()
            return cur.rowcount
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    except Exception as e:
        conn.rollback()
        raise e


def execute_db(sql, args=(), fetch=False):
    """Execute INSERT/UPDATE/DELETE (reuses per-request connection)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(sql, args)
        conn.commit()
        if fetch:
            return cur.fetchone()
        return cur.rowcount
    except Exception as e:
        conn.rollback()
        raise e


# ─────────────────────────────────────────────
# Auth Helpers
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles and "ADMIN" not in (session.get("role", ""),):
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def current_user():
    return {
        "id": session.get("user_id"),
        "name": session.get("user_name"),
        "role": session.get("role"),
        "email": session.get("email"),
    }


def convert_decimals(obj):
    """Convert Decimal values to float for JSON serialization."""
    from decimal import Decimal
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_decimals(v) for v in obj]
    elif isinstance(obj, Decimal):
        return float(obj)
    return obj


# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        user = query_db(
            """SELECT u.id, u.email, u.password_hash, u.status,
                      r.role_name, up.full_name
               FROM users u
               JOIN roles r ON u.role_id = r.id
               LEFT JOIN user_profiles up ON u.id = up.user_id
               WHERE u.email = %s""",
            (email,), one=True
        )

        if not user:
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        if user["status"] != "ACTIVE":
            flash("Your account is inactive.", "warning")
            return render_template("login.html")

        if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"]   = str(user["id"])
        session["user_name"] = user["full_name"] or email.split("@")[0]
        session["role"]      = user["role_name"]
        session["email"]     = user["email"]

        execute_db("UPDATE users SET last_login=%s WHERE id=%s",
                   (datetime.utcnow(), user["id"]))

        role = user["role_name"]
        if role in ("ADMIN", "OWNER"):
            return redirect(url_for("dashboard"))
        elif role == "PRODUCTION_MANAGER":
            return redirect(url_for("production"))
        elif role == "SALESMAN":
            return redirect(url_for("delivery"))
        elif role == "RETAIL_SHOP":
            return redirect(url_for("shop_portal"))
        elif role == "ACCOUNTANT":
            return redirect(url_for("dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    today = date.today()

    # Single CTE query replaces 5 separate scalar queries
    stats = query_db(
        """WITH
           sales_today AS (
               SELECT COALESCE(SUM(i.selling_price * d.delivered_quantity),0) AS total_sales,
                      COUNT(DISTINCT d.shop_id) AS shops_count,
                      COUNT(d.id) AS deliveries_count
               FROM deliveries d
               JOIN inventory i ON d.inventory_id = i.id
               JOIN delivery_trips dt ON d.trip_id = dt.id
               WHERE dt.trip_date = %s AND d.status = 'DELIVERED'
           ),
           cash_today AS (
               SELECT COALESCE(SUM(amount),0) AS cash_total
               FROM payments WHERE DATE(payment_date) = %s AND status != 'CANCELLED'
           ),
           outstanding AS (
               SELECT COALESCE(SUM(balance),0) AS outstanding_total, COUNT(*) AS outstanding_count
               FROM invoices WHERE status IN ('PENDING','PARTIAL','OVERDUE')
           )
           SELECT s.total_sales, s.shops_count, s.deliveries_count,
                  c.cash_total, o.outstanding_total, o.outstanding_count,
                  (SELECT COUNT(*) FROM production_waste WHERE decision='PENDING') AS waste_count,
                  (SELECT COUNT(*) FROM feedback WHERE status='OPEN') AS feedback_count
           FROM sales_today s, cash_today c, outstanding o""",
        (today, today), one=True
    )

    # Low stock, production, orders, chart — still 4 queries but now all on the pooled connection
    low_stock = query_db(
        """SELECT material_name, current_stock, reorder_level, unit
           FROM raw_materials
           WHERE current_stock <= reorder_level AND is_active = true
           ORDER BY (current_stock / NULLIF(reorder_level,0)) ASC
           LIMIT 5"""
    )

    production = query_db(
        """SELECT pb.batch_number, p.product_name, pb.planned_quantity,
                  pb.actual_quantity, pb.status
           FROM production_batches pb
           JOIN products p ON pb.product_id = p.id
           WHERE pb.production_date = %s
           ORDER BY pb.created_at DESC LIMIT 10""",
        (today,)
    )

    orders = query_db(
        """SELECT co.order_number, rs.shop_name, co.status,
                  co.total_amount, co.delivery_date
           FROM customer_orders co
           JOIN retail_shops rs ON co.shop_id = rs.id
           ORDER BY co.created_at DESC LIMIT 8"""
    )

    chart_data = query_db(
        """SELECT DATE(dt.trip_date) as sale_date,
                  COALESCE(SUM(i.selling_price * d.delivered_quantity), 0) as total
           FROM delivery_trips dt
           LEFT JOIN deliveries d ON dt.id = d.trip_id AND d.status = 'DELIVERED'
           LEFT JOIN inventory i ON d.inventory_id = i.id
           WHERE dt.trip_date >= CURRENT_DATE - INTERVAL '6 days'
           GROUP BY DATE(dt.trip_date)
           ORDER BY sale_date ASC"""
    )

    stats = convert_decimals(stats)
    sales = {
        "total_sales": stats["total_sales"],
        "shops_count": stats["shops_count"],
        "deliveries_count": stats["deliveries_count"],
    }
    cash        = {"total": stats["cash_total"]}
    outstanding = {"total": stats["outstanding_total"], "count": stats["outstanding_count"]}
    waste_pending    = {"count": stats["waste_count"]}
    feedback_pending = {"count": stats["feedback_count"]}

    return render_template("dashboard.html",
        user=current_user(),
        today=today,
        sales=sales,
        cash=cash,
        outstanding=outstanding,
        low_stock=convert_decimals(list(low_stock)),
        production=convert_decimals(list(production)),
        orders=convert_decimals(list(orders)),
        chart_data=convert_decimals(list(chart_data)),
        waste_pending=waste_pending,
        feedback_pending=feedback_pending,
    )


# ─────────────────────────────────────────────
# PRODUCTION MANAGEMENT
# ─────────────────────────────────────────────

def deduct_raw_materials(batch_id, actual_quantity):
    """
    Deduct raw materials from inventory when a production batch is completed.
    All deductions happen in a single atomic transaction.
    """
    conn = get_db()
    try:
        cur = conn.cursor()

        cur.execute("SELECT product_id, batch_number FROM production_batches WHERE id=%s", (batch_id,))
        batch = cur.fetchone()
        if not batch:
            return False

        cur.execute(
            "SELECT material_id, quantity_required FROM product_recipes WHERE product_id=%s",
            (batch["product_id"],)
        )
        recipes = cur.fetchall()

        if not recipes:
            return True  # No recipe defined for this product

        user_id = session.get("user_id")
        for recipe in recipes:
            qty_needed = float(recipe["quantity_required"]) * float(actual_quantity)

            cur.execute(
                "UPDATE raw_materials SET current_stock = current_stock - %s, updated_at=NOW() WHERE id=%s",
                (qty_needed, recipe["material_id"])
            )
            cur.execute(
                """INSERT INTO raw_material_transactions
                   (material_id, transaction_type, quantity, batch_number,
                    reference_type, reference_id, transaction_date, created_by)
                   VALUES (%s, 'USAGE', %s, %s, 'PRODUCTION', %s, CURRENT_DATE, %s)""",
                (recipe["material_id"], qty_needed, batch["batch_number"], batch_id, user_id)
            )

        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error deducting materials: {e}")
        return False


@app.route("/production")
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def production():
    # Optimized queries with pagination - only load recent batches
    batches = query_db(
        """SELECT pb.id, pb.batch_number, p.product_name, pb.planned_quantity,
                  pb.actual_quantity, pb.waste_quantity, pb.status,
                  pb.production_date, up.full_name as manager_name
           FROM production_batches pb
           JOIN products p ON pb.product_id = p.id
           JOIN users u ON pb.production_manager_id = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           WHERE pb.production_date >= CURRENT_DATE - INTERVAL '7 days'
           ORDER BY pb.production_date DESC, pb.created_at DESC
           LIMIT 50"""
    )

    # Get only active products (cached in frontend)
    products = query_db(
        "SELECT id, product_name FROM products WHERE is_active=true ORDER BY product_name"
    )

    # Get only materials that are low or active (optimized)
    raw_materials = query_db(
        """SELECT id, material_name, current_stock, unit, reorder_level
           FROM raw_materials WHERE is_active=true
           ORDER BY material_name"""
    )

    # Get pending waste items (critical - affects revenue)
    waste_queue = query_db(
        """SELECT pw.id, p.product_name, pb.batch_number,
                  pw.waste_type, pw.quantity, pw.reason, pw.decision,
                  pb.production_date
           FROM production_waste pw
           JOIN production_batches pb ON pw.batch_id = pb.id
           JOIN products p ON pb.product_id = p.id
           WHERE pw.decision = 'PENDING'
           ORDER BY pw.created_at DESC
           LIMIT 20"""
    )

    return render_template("production.html",
        user=current_user(),
        batches=convert_decimals(list(batches)),
        products=convert_decimals(list(products)),
        raw_materials=convert_decimals(list(raw_materials)),
        waste_queue=convert_decimals(list(waste_queue)),
    )


@app.route("/production/batch/new", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def new_batch():
    product_id  = request.form.get("product_id")
    planned_qty = request.form.get("planned_quantity")
    prod_date   = request.form.get("production_date")
    notes       = request.form.get("notes", "")

    batch_number = f"BATCH-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    execute_db(
        """INSERT INTO production_batches
           (batch_number, product_id, planned_quantity, production_date,
            production_manager_id, status, notes, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,'PLANNED',%s,NOW(),NOW())""",
        (batch_number, product_id, planned_qty, prod_date, session["user_id"], notes)
    )
    flash(f"Production batch {batch_number} created!", "success")
    return redirect(url_for("production"))


@app.route("/production/batch/<batch_id>/update", methods=["POST"])
@login_required
def update_batch(batch_id):
    action      = request.form.get("action")
    actual_qty  = request.form.get("actual_quantity")
    waste_qty   = request.form.get("waste_quantity", 0)
    status      = request.form.get("status")

    if action == "start":
        execute_db(
            """UPDATE production_batches
               SET status='IN_PROGRESS', start_time=NOW(), updated_at=NOW()
               WHERE id=%s""", (batch_id,)
        )
        flash("Production started.", "success")

    elif action == "complete":
        execute_db(
            """UPDATE production_batches
               SET status='COMPLETED', actual_quantity=%s, waste_quantity=%s,
                   end_time=NOW(), updated_at=NOW()
               WHERE id=%s""",
            (actual_qty, waste_qty, batch_id)
        )
        
        # Deduct raw materials from inventory
        if deduct_raw_materials(batch_id, actual_qty):
            flash("Production completed and inventory updated!", "success")
        else:
            flash("Production completed but inventory update had errors. Check logs.", "warning")

    return redirect(url_for("production"))


@app.route("/production/recipes")
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def recipes():
    products = query_db(
        "SELECT id, product_name FROM products WHERE is_active=true ORDER BY product_name"
    )
    raw_materials = query_db(
        "SELECT id, material_name, unit, cost_per_unit FROM raw_materials WHERE is_active=true ORDER BY material_name"
    )
    recipe_rows = query_db(
        """SELECT pr.id, p.product_name, rm.material_name, pr.quantity_required, pr.unit,
                  pr.cost_per_unit, p.id as product_id
           FROM product_recipes pr
           JOIN products p ON pr.product_id = p.id
           JOIN raw_materials rm ON pr.material_id = rm.id
           ORDER BY p.product_name, rm.material_name"""
    )
    return render_template("recipes.html",
        user=current_user(),
        products=convert_decimals(list(products)),
        raw_materials=convert_decimals(list(raw_materials)),
        recipe_rows=convert_decimals(list(recipe_rows)),
    )


@app.route("/production/recipes/add", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def add_recipe():
    product_id   = request.form.get("product_id")
    material_id  = request.form.get("material_id")
    qty_required = request.form.get("quantity_required")
    unit         = request.form.get("unit")

    cost = query_db(
        "SELECT cost_per_unit FROM raw_materials WHERE id=%s", (material_id,), one=True
    )
    cost_per_unit = float(cost["cost_per_unit"]) if cost else 0

    try:
        execute_db(
            """INSERT INTO product_recipes (product_id, material_id, quantity_required, unit, cost_per_unit)
               VALUES (%s,%s,%s,%s,%s)
               ON CONFLICT (product_id, material_id) DO UPDATE
               SET quantity_required=%s, unit=%s, cost_per_unit=%s, updated_at=NOW()""",
            (product_id, material_id, qty_required, unit, cost_per_unit,
             qty_required, unit, cost_per_unit)
        )
        flash("Recipe item saved.", "success")
    except Exception as e:
        flash(f"Error saving recipe: {e}", "danger")
    return redirect(url_for("recipes"))


@app.route("/production/recipes/<int:recipe_id>/delete", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def delete_recipe(recipe_id):
    execute_db("DELETE FROM product_recipes WHERE id=%s", (recipe_id,))
    flash("Recipe item removed.", "success")
    return redirect(url_for("recipes"))


@app.route("/production/waste/<int:waste_id>/decide", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def decide_waste(waste_id):
    decision = request.form.get("decision")  # REFURBISH or WASTE
    execute_db(
        """UPDATE production_waste
           SET decision=%s, decided_by=%s, decided_at=NOW(), updated_at=NOW()
           WHERE id=%s""",
        (decision, session["user_id"], waste_id)
    )
    flash(f"Waste marked as: {decision}", "success")
    return redirect(url_for("production"))


# ─────────────────────────────────────────────
# PACKING UNIT
# ─────────────────────────────────────────────
@app.route("/production/packing")
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def packing():
    completed_batches = query_db(
        """SELECT pb.id, pb.batch_number, p.product_name, p.pack_size,
                  pb.actual_quantity, pb.production_date,
                  COALESCE(SUM(pkb.packs_created), 0) as already_packed
           FROM production_batches pb
           JOIN products p ON pb.product_id = p.id
           LEFT JOIN packaging_batches pkb ON pb.id = pkb.production_batch_id
           WHERE pb.status = 'COMPLETED'
             AND pb.production_date >= CURRENT_DATE - INTERVAL '30 days'
           GROUP BY pb.id, p.product_name, p.pack_size
           ORDER BY pb.production_date DESC"""
    )
    packing_history = query_db(
        """SELECT pkb.id, pkb.packs_created, pkb.pack_size, pkb.packaging_cost,
                  pkb.packaging_date, pb.batch_number, p.product_name,
                  up.full_name as packed_by
           FROM packaging_batches pkb
           JOIN production_batches pb ON pkb.production_batch_id = pb.id
           JOIN products p ON pkb.product_id = p.id
           LEFT JOIN users u ON pkb.created_by = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           ORDER BY pkb.created_at DESC LIMIT 50"""
    )
    return render_template("packing.html",
        user=current_user(),
        completed_batches=convert_decimals(list(completed_batches)),
        packing_history=convert_decimals(list(packing_history)),
    )


@app.route("/production/packing/new", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def new_packing():
    batch_id       = request.form.get("batch_id")
    packs_created  = int(request.form.get("packs_created", 0))
    packaging_cost = float(request.form.get("packaging_cost", 0))
    labour_cost    = float(request.form.get("labour_cost", 0))
    notes          = request.form.get("notes", "")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT pb.id, pb.actual_quantity, pb.total_cost, p.id as product_id,
                      p.product_name, p.barcode_prefix, p.pack_size, p.unit_price, p.shelf_life_days
               FROM production_batches pb JOIN products p ON pb.product_id = p.id
               WHERE pb.id=%s""", (batch_id,)
        )
        batch = cur.fetchone()
        if not batch or packs_created <= 0:
            flash("Invalid batch or pack count.", "danger")
            return redirect(url_for("packing"))

        total_cost = float(batch["total_cost"] or 0) + packaging_cost + labour_cost
        cost_per_pack = round(total_cost / packs_created, 2) if packs_created else 0

        cur.execute(
            """INSERT INTO packaging_batches
               (production_batch_id, product_id, pack_size, packs_created,
                packaging_cost, packaging_date, created_by, created_at)
               VALUES (%s,%s,%s,%s,%s,CURRENT_DATE,%s,NOW()) RETURNING id""",
            (batch_id, batch["product_id"], batch["pack_size"],
             packs_created, packaging_cost + labour_cost, session["user_id"])
        )
        pkg_id = cur.fetchone()["id"]

        expiry = None
        if batch["shelf_life_days"]:
            cur.execute("SELECT CURRENT_DATE + INTERVAL '%s days' as exp", (batch["shelf_life_days"],))
            expiry = cur.fetchone()["exp"]

        barcode = f"{batch['barcode_prefix']}-{datetime.now().strftime('%Y%m%d')}-{str(pkg_id)[:8]}"
        cur.execute(
            """INSERT INTO inventory
               (product_id, packaging_batch_id, barcode, pack_size,
                quantity_available, cost_per_unit, selling_price, status, expiry_date, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'AVAILABLE',%s,NOW())""",
            (batch["product_id"], pkg_id, barcode, batch["pack_size"],
             packs_created, cost_per_pack, float(batch["unit_price"]), expiry)
        )
        cur.execute(
            "UPDATE production_batches SET total_cost=%s, updated_at=NOW() WHERE id=%s",
            (total_cost, batch_id)
        )
        conn.commit()
        flash(f"Packed {packs_created} packs. Added to inventory with barcode {barcode}.", "success")
    except Exception as e:
        conn.rollback()
        print(f"Packing error: {e}")
        flash("Error creating packing batch.", "danger")
    return redirect(url_for("packing"))


# ─────────────────────────────────────────────
# PRODUCTION COSTS (Fuel / Gas / Labour)
# ─────────────────────────────────────────────
@app.route("/production/batch/<batch_id>/cost/add", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def add_batch_cost(batch_id):
    cost_type   = request.form.get("cost_type")
    amount      = float(request.form.get("amount", 0))
    description = request.form.get("description", "")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO production_costs (batch_id,cost_type,amount,description,created_at) VALUES (%s,%s,%s,%s,NOW())",
            (batch_id, cost_type, amount, description)
        )
        cur.execute(
            "UPDATE production_batches SET total_cost = COALESCE(total_cost,0) + %s, updated_at=NOW() WHERE id=%s",
            (amount, batch_id)
        )
        conn.commit()
        flash(f"{cost_type} cost of ₹{amount:.2f} recorded.", "success")
    except Exception as e:
        conn.rollback()
        flash("Error recording cost.", "danger")
    return redirect(url_for("production"))


@app.route("/production/batch/<batch_id>/cost/<int:cost_id>/delete", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def delete_batch_cost(batch_id, cost_id):
    cost = query_db("SELECT amount FROM production_costs WHERE id=%s AND batch_id=%s", (cost_id, batch_id), one=True)
    if cost:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM production_costs WHERE id=%s", (cost_id,))
        cur.execute(
            "UPDATE production_batches SET total_cost = COALESCE(total_cost,0) - %s, updated_at=NOW() WHERE id=%s",
            (float(cost["amount"]), batch_id)
        )
        conn.commit()
        flash("Cost entry removed.", "success")
    return redirect(url_for("production"))


# ─────────────────────────────────────────────
# PRODUCTION GOALS / TARGETS
# ─────────────────────────────────────────────
@app.route("/production/goals")
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def production_goals():
    products = query_db("SELECT id, product_name FROM products WHERE is_active=true ORDER BY product_name")
    goals = query_db(
        """SELECT pg.id, p.product_name, pg.target_month, pg.target_year,
                  pg.target_quantity,
                  COALESCE(SUM(pb.actual_quantity),0) as actual_quantity
           FROM production_goals pg
           JOIN products p ON pg.product_id = p.id
           LEFT JOIN production_batches pb
             ON pb.product_id = pg.product_id
            AND EXTRACT(MONTH FROM pb.production_date) = pg.target_month
            AND EXTRACT(YEAR  FROM pb.production_date) = pg.target_year
            AND pb.status = 'COMPLETED'
           GROUP BY pg.id, p.product_name, pg.target_month, pg.target_year, pg.target_quantity
           ORDER BY pg.target_year DESC, pg.target_month DESC, p.product_name"""
    )
    return render_template("goals.html",
        user=current_user(),
        products=list(products),
        goals=convert_decimals(list(goals)),
        current_month=datetime.now().month,
        current_year=datetime.now().year,
    )


@app.route("/production/goals/set", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER", "PRODUCTION_MANAGER")
def set_goal():
    product_id = request.form.get("product_id")
    month      = int(request.form.get("month"))
    year       = int(request.form.get("year"))
    target_qty = int(request.form.get("target_quantity"))
    execute_db(
        """INSERT INTO production_goals (product_id, target_month, target_year, target_quantity, created_at, updated_at)
           VALUES (%s,%s,%s,%s,NOW(),NOW())
           ON CONFLICT (product_id, target_month, target_year)
           DO UPDATE SET target_quantity=%s, updated_at=NOW()""",
        (product_id, month, year, target_qty, target_qty)
    )
    flash("Production goal saved.", "success")
    return redirect(url_for("production_goals"))


@app.route("/production/goals/<int:goal_id>/delete", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def delete_goal(goal_id):
    execute_db("DELETE FROM production_goals WHERE id=%s", (goal_id,))
    flash("Goal removed.", "success")
    return redirect(url_for("production_goals"))


# ─────────────────────────────────────────────
# FEEDBACK MANAGEMENT
# ─────────────────────────────────────────────
@app.route("/feedback")
@login_required
@role_required("ADMIN", "OWNER")
def feedback_list():
    items = query_db(
        """SELECT f.id, rs.shop_name, p.product_name, f.rating,
                  f.feedback_type, f.comments, f.status,
                  f.created_at, f.resolution_notes,
                  up.full_name as resolved_by_name
           FROM feedback f
           JOIN retail_shops rs ON f.shop_id = rs.id
           LEFT JOIN products p ON f.product_id = p.id
           LEFT JOIN users u ON f.resolved_by = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           ORDER BY CASE f.status WHEN 'OPEN' THEN 0 ELSE 1 END,
                    f.created_at DESC"""
    )
    return render_template("feedback.html",
        user=current_user(),
        items=list(items),
    )


@app.route("/feedback/<feedback_id>/resolve", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def resolve_feedback(feedback_id):
    notes = request.form.get("resolution_notes", "")
    execute_db(
        """UPDATE feedback
           SET status='RESOLVED', resolved_by=%s, resolved_at=NOW(),
               resolution_notes=%s, updated_at=NOW()
           WHERE id=%s""",
        (session["user_id"], notes, feedback_id)
    )
    flash("Feedback resolved.", "success")
    return redirect(url_for("feedback_list"))


@app.route("/feedback/submit", methods=["POST"])
def submit_feedback():
    shop_id       = request.form.get("shop_id")
    product_id    = request.form.get("product_id") or None
    rating        = request.form.get("rating")
    feedback_type = request.form.get("feedback_type", "OTHER")
    comments      = request.form.get("comments", "")
    if not shop_id or not comments:
        flash("Please fill in all required fields.", "danger")
        return redirect(url_for("shop_portal"))
    execute_db(
        """INSERT INTO feedback (shop_id, product_id, rating, feedback_type, comments, status, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,'OPEN',NOW(),NOW())""",
        (shop_id, product_id, rating, feedback_type, comments)
    )
    flash("Thank you! Your feedback has been submitted.", "success")
    return redirect(url_for("shop_portal"))


# ─────────────────────────────────────────────
# BARCODE SCAN LOOKUP (JSON API)
# ─────────────────────────────────────────────
@app.route("/api/scan/<barcode>")
@login_required
def scan_barcode(barcode):
    inv = query_db(
        """SELECT i.id, i.barcode, i.pack_size, i.quantity_available,
                  i.selling_price, i.cost_per_unit, i.status, i.expiry_date,
                  p.product_name, p.category
           FROM inventory i JOIN products p ON i.product_id = p.id
           WHERE i.barcode = %s""",
        (barcode,), one=True
    )
    if inv:
        return jsonify({"found": True, "type": "inventory", "data": convert_decimals(dict(inv))})
    mat = query_db(
        "SELECT id, material_name, unit, current_stock FROM raw_materials WHERE barcode=%s",
        (barcode,), one=True
    )
    if mat:
        return jsonify({"found": True, "type": "raw_material", "data": convert_decimals(dict(mat))})
    return jsonify({"found": False})


# ─────────────────────────────────────────────
# INVOICE PDF DOWNLOAD
# ─────────────────────────────────────────────
@app.route("/invoices/<invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    import io

    inv = query_db(
        """SELECT inv.*, rs.shop_name, rs.address, rs.phone
           FROM invoices inv JOIN retail_shops rs ON inv.shop_id = rs.id
           WHERE inv.id=%s""",
        (invoice_id,), one=True
    )
    if not inv:
        flash("Invoice not found.", "danger")
        return redirect(url_for("payments"))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("<b>Milan Bakery</b>", styles["Title"]))
    story.append(Paragraph("Tax Invoice", styles["Heading2"]))
    story.append(Spacer(1, 12))

    meta = [
        ["Invoice No:", inv["invoice_number"], "Date:", str(inv["invoice_date"])],
        ["Shop:", inv["shop_name"],            "Due Date:", str(inv["due_date"])],
        ["Phone:", inv["phone"] or "–",        "Status:", inv["status"]],
    ]
    t = Table(meta, colWidths=[80, 200, 70, 130])
    t.setStyle(TableStyle([("FONTSIZE", (0,0), (-1,-1), 9)]))
    story.append(t)
    story.append(Spacer(1, 16))

    data = [["Description", "Amount (₹)"]]
    data.append(["Subtotal", f"{float(inv['subtotal']):.2f}"])
    data.append([f"GST ({inv['gst_percentage']}%)", f"{float(inv['gst_amount']):.2f}"])
    data.append(["Total", f"{float(inv['total_amount']):.2f}"])
    data.append(["Amount Paid", f"{float(inv['amount_paid']):.2f}"])
    data.append(["Balance Due", f"{float(inv['balance']):.2f}"])

    tbl = Table(data, colWidths=[350, 130])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#8B4513")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#FFF8E7")]),
        ("FONTNAME",    (0,-1), (-1,-1), "Helvetica-Bold"),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
    ]))
    story.append(tbl)
    doc.build(story)
    buf.seek(0)

    from flask import send_file
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"Invoice-{inv['invoice_number']}.pdf",
                     as_attachment=True)


# ─────────────────────────────────────────────
# INVENTORY
# ─────────────────────────────────────────────
@app.route("/inventory")
@login_required
def inventory():
    # Finished goods — include one representative barcode per group for label printing
    finished = query_db(
        """SELECT p.product_name, i.pack_size,
                  SUM(i.quantity_available) as total_available,
                  MIN(i.expiry_date) as nearest_expiry,
                  AVG(i.selling_price) as avg_price,
                  i.status,
                  MIN(i.barcode) as barcode
           FROM inventory i
           JOIN products p ON i.product_id = p.id
           WHERE i.status IN ('AVAILABLE','RESERVED')
           GROUP BY p.product_name, i.pack_size, i.status
           ORDER BY p.product_name"""
    )

    # Raw materials
    raw_mats = query_db(
        """SELECT rm.id, rm.material_name, rm.current_stock, rm.unit,
                  rm.reorder_level, rm.cost_per_unit, s.supplier_name,
                  CASE WHEN rm.current_stock <= rm.reorder_level THEN 'LOW'
                       ELSE 'OK' END as stock_status
           FROM raw_materials rm
           LEFT JOIN suppliers s ON rm.supplier_id = s.id
           WHERE rm.is_active = true
           ORDER BY rm.material_name"""
    )

    products = query_db(
        "SELECT id, product_name, category FROM products WHERE is_active=true ORDER BY product_name"
    )

    return render_template("inventory.html",
        user=current_user(),
        finished=convert_decimals(list(finished)),
        raw_mats=convert_decimals(list(raw_mats)),
        products=convert_decimals(list(products)),
    )


@app.route("/inventory/stock-in", methods=["POST"])
@login_required
def stock_in():
    material_id = request.form.get("material_id")
    quantity    = float(request.form.get("quantity", 0))
    cost        = float(request.form.get("cost_per_unit", 0))
    supplier_id = request.form.get("supplier_id")
    notes       = request.form.get("notes", "")

    # Update raw material stock
    execute_db(
        "UPDATE raw_materials SET current_stock = current_stock + %s, updated_at=NOW() WHERE id=%s",
        (quantity, material_id)
    )
    # Log transaction
    execute_db(
        """INSERT INTO raw_material_transactions
           (material_id, transaction_type, quantity, cost, supplier_id,
            reference_type, transaction_date, notes, created_by, created_at)
           VALUES (%s,'IN',%s,%s,%s,'PURCHASE',CURRENT_DATE,%s,%s,NOW())""",
        (material_id, quantity, cost * quantity, supplier_id, notes, session["user_id"])
    )
    flash("Stock updated successfully.", "success")
    return redirect(url_for("inventory"))


# ─────────────────────────────────────────────
# DELIVERY MANAGEMENT
# ─────────────────────────────────────────────
@app.route("/delivery")
@login_required
def delivery():
    role = session.get("role")
    today = date.today()

    if role == "SALESMAN":
        # Salesman sees only their trips
        trips = query_db(
            """SELECT dt.id, dt.trip_number, dt.trip_date, dt.trip_sequence,
                      dt.status, dt.allowance_amount,
                      dt.cash_collected, dt.digital_collected,
                      COUNT(d.id) as total_deliveries,
                      SUM(CASE WHEN d.status='DELIVERED' THEN 1 ELSE 0 END) as completed
               FROM delivery_trips dt
               LEFT JOIN deliveries d ON dt.id = d.trip_id
               JOIN salesmen s ON dt.salesman_id = s.id
               JOIN users u ON s.user_id = u.id
               WHERE u.id = %s AND dt.trip_date >= CURRENT_DATE - INTERVAL '7 days'
               GROUP BY dt.id
               ORDER BY dt.trip_date DESC, dt.trip_sequence""",
            (session["user_id"],)
        )
    else:
        trips = query_db(
            """SELECT dt.id, dt.trip_number, dt.trip_date, dt.trip_sequence,
                      dt.status, dt.allowance_amount,
                      dt.cash_collected, dt.digital_collected,
                      up.full_name as salesman_name,
                      COUNT(d.id) as total_deliveries,
                      SUM(CASE WHEN d.status='DELIVERED' THEN 1 ELSE 0 END) as completed
               FROM delivery_trips dt
               JOIN salesmen s ON dt.salesman_id = s.id
               JOIN users u ON s.user_id = u.id
               LEFT JOIN user_profiles up ON u.id = up.user_id
               LEFT JOIN deliveries d ON dt.id = d.trip_id
               WHERE dt.trip_date >= CURRENT_DATE - INTERVAL '7 days'
               GROUP BY dt.id, up.full_name
               ORDER BY dt.trip_date DESC, dt.trip_sequence"""
        )

    salesmen = query_db(
        """SELECT s.id, up.full_name, s.employee_code, s.vehicle_number
           FROM salesmen s
           JOIN users u ON s.user_id = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           WHERE s.is_active = true"""
    )

    shops = query_db(
        "SELECT id, shop_name, address FROM retail_shops WHERE is_active=true ORDER BY shop_name"
    )

    # Returns pending decision
    returns = query_db(
        """SELECT dr.id, rs.shop_name, p.product_name, dr.quantity_returned,
                  dr.return_reason, dr.return_condition, dr.decision,
                  dr.created_at
           FROM delivery_returns dr
           JOIN retail_shops rs ON dr.shop_id = rs.id
           JOIN inventory i ON dr.inventory_id = i.id
           JOIN products p ON i.product_id = p.id
           WHERE dr.decision = 'PENDING'
           ORDER BY dr.created_at DESC"""
    )

    return render_template("delivery.html",
        user=current_user(),
        trips=convert_decimals(list(trips)),
        salesmen=convert_decimals(list(salesmen)),
        shops=convert_decimals(list(shops)),
        returns=convert_decimals(list(returns)),
        today=today,
    )


@app.route("/delivery/trip/new", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def new_trip():
    salesman_id = request.form.get("salesman_id")
    trip_date   = request.form.get("trip_date")
    sequence    = request.form.get("trip_sequence", 1)
    allowance   = request.form.get("allowance", 500)

    trip_number = f"TRIP-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    execute_db(
        """INSERT INTO delivery_trips
           (trip_number, salesman_id, trip_date, trip_sequence,
            allowance_amount, status, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,'PLANNED',NOW(),NOW())""",
        (trip_number, salesman_id, trip_date, sequence, allowance)
    )
    flash(f"Trip {trip_number} created!", "success")
    return redirect(url_for("delivery"))


@app.route("/delivery/trip/<trip_id>/status", methods=["POST"])
@login_required
def update_trip_status(trip_id):
    status = request.form.get("status")
    execute_db(
        "UPDATE delivery_trips SET status=%s, updated_at=NOW() WHERE id=%s",
        (status, trip_id)
    )
    flash(f"Trip status updated to {status}.", "success")
    return redirect(url_for("delivery"))


@app.route("/delivery/return/<int:return_id>/decide", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def decide_return(return_id):
    decision = request.form.get("decision")
    execute_db(
        """UPDATE delivery_returns
           SET decision=%s, decided_by=%s, decided_at=NOW(), updated_at=NOW()
           WHERE id=%s""",
        (decision, session["user_id"], return_id)
    )
    flash(f"Return marked as: {decision}", "success")
    return redirect(url_for("delivery"))


# ─────────────────────────────────────────────
# ORDERS MANAGEMENT
# ─────────────────────────────────────────────
@app.route("/orders")
@login_required
def orders():
    all_orders = query_db(
        """SELECT co.id, co.order_number, rs.shop_name,
                  co.order_date, co.delivery_date,
                  co.status, co.total_amount,
                  co.special_instructions,
                  COUNT(coi.id) as item_count
           FROM customer_orders co
           JOIN retail_shops rs ON co.shop_id = rs.id
           LEFT JOIN customer_order_items coi ON co.id = coi.order_id
           GROUP BY co.id, rs.shop_name
           ORDER BY co.order_date DESC
           LIMIT 50"""
    )

    return render_template("orders.html",
        user=current_user(),
        orders=convert_decimals(list(all_orders)),
    )


@app.route("/orders/<order_id>")
@login_required
def order_detail(order_id):
    order = query_db(
        """SELECT co.*, rs.shop_name, rs.phone, rs.address
           FROM customer_orders co
           JOIN retail_shops rs ON co.shop_id = rs.id
           WHERE co.id = %s""",
        (order_id,), one=True
    )
    items = query_db(
        """SELECT coi.*, p.product_name
           FROM customer_order_items coi
           JOIN products p ON coi.product_id = p.id
           WHERE coi.order_id = %s""",
        (order_id,)
    )
    return render_template("order_detail.html",
        user=current_user(), order=convert_decimals(order), items=convert_decimals(list(items)))


@app.route("/orders/<order_id>/update", methods=["POST"])
@login_required
def update_order(order_id):
    status = request.form.get("status")
    execute_db(
        "UPDATE customer_orders SET status=%s, updated_at=NOW() WHERE id=%s",
        (status, order_id)
    )
    flash("Order status updated.", "success")
    return redirect(url_for("orders"))


# ─────────────────────────────────────────────
# RETAIL SHOP PORTAL
# ─────────────────────────────────────────────
@app.route("/shop")
def shop_portal():
    """Public portal for retail shop owners to place orders."""
    products = query_db(
        """SELECT p.id, p.product_name, p.category, p.pack_size,
                  p.unit_price, p.description,
                  COALESCE(SUM(i.quantity_available),0) as stock
           FROM products p
           LEFT JOIN inventory i ON p.id = i.product_id AND i.status='AVAILABLE'
           WHERE p.is_active = true
           GROUP BY p.id
           ORDER BY p.category, p.product_name"""
    )

    shops = query_db(
        "SELECT id, shop_name FROM retail_shops WHERE is_active=true ORDER BY shop_name"
    )

    return render_template("shop_portal.html",
        products=convert_decimals(list(products)),
        shops=convert_decimals(list(shops)),
    )


@app.route("/shop/order", methods=["POST"])
def place_order():
    shop_id      = request.form.get("shop_id")
    delivery_date = request.form.get("delivery_date")
    instructions = request.form.get("instructions", "")
    product_ids  = request.form.getlist("product_id[]")
    quantities   = request.form.getlist("quantity[]")

    if not shop_id or not product_ids:
        flash("Please select a shop and at least one product.", "danger")
        return redirect(url_for("shop_portal"))

    # Generate unique order number
    _now = datetime.now()
    order_number = f"ORD-{_now.strftime('%Y%m%d%H%M%S')}{_now.microsecond:04d}"

    # Calculate total
    total = 0
    items = []
    for pid, qty in zip(product_ids, quantities):
        if int(qty) > 0:
            product = query_db(
                "SELECT id, unit_price, product_name FROM products WHERE id=%s",
                (pid,), one=True
            )
            if product:
                subtotal = product["unit_price"] * int(qty)
                total += subtotal
                items.append((pid, qty, product["unit_price"], subtotal))

    if not items:
        flash("No valid items in order.", "danger")
        return redirect(url_for("shop_portal"))

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO customer_orders
               (order_number, shop_id, delivery_date, status,
                special_instructions, total_amount, created_at, updated_at)
               VALUES (%s,%s,%s,'PENDING',%s,%s,NOW(),NOW()) RETURNING id""",
            (order_number, shop_id, delivery_date, instructions, total)
        )
        order_id = cur.fetchone()["id"]
        for pid, qty, price, subtotal in items:
            cur.execute(
                """INSERT INTO customer_order_items
                   (order_id, product_id, pack_size, quantity, unit_price,
                    total_price, created_at)
                   VALUES (%s,%s,1,%s,%s,%s,NOW())""",
                (order_id, pid, qty, price, subtotal)
            )
        conn.commit()
        flash(f"Order {order_number} placed! We'll deliver on {delivery_date}.", "success")
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Order error: {type(e).__name__}: {e}")
        flash("Error placing order. Please try again.", "danger")

    return redirect(url_for("shop_portal"))


# ─────────────────────────────────────────────
# PAYMENTS
# ─────────────────────────────────────────────
@app.route("/payments")
@login_required
def payments():
    all_payments = query_db(
        """SELECT p.payment_number, p.payment_type, p.amount,
                  p.payment_date, p.status, p.reference_number,
                  rs.shop_name, up.full_name as collected_by
           FROM payments p
           JOIN retail_shops rs ON p.shop_id = rs.id
           LEFT JOIN salesmen s ON p.collected_by = s.id
           LEFT JOIN users u ON s.user_id = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           ORDER BY p.payment_date DESC
           LIMIT 50"""
    )

    outstanding = query_db(
        """SELECT rs.id, rs.shop_name, rs.phone,
                  SUM(inv.balance) as total_outstanding,
                  COUNT(inv.id) as invoice_count,
                  MIN(inv.due_date) as oldest_due
           FROM retail_shops rs
           JOIN invoices inv ON rs.id = inv.shop_id
           WHERE inv.status IN ('PENDING','PARTIAL','OVERDUE')
           GROUP BY rs.id, rs.shop_name, rs.phone
           ORDER BY total_outstanding DESC"""
    )

    shops = query_db(
        "SELECT id, shop_name FROM retail_shops WHERE is_active=true ORDER BY shop_name"
    )

    return render_template("payments.html",
        user=current_user(),
        payments=convert_decimals(list(all_payments)),
        outstanding=convert_decimals(list(outstanding)),
        shops=convert_decimals(list(shops)),
    )


@app.route("/payments/record", methods=["POST"])
@login_required
def record_payment():
    shop_id    = request.form.get("shop_id")
    amount     = request.form.get("amount")
    ptype      = request.form.get("payment_type")
    reference  = request.form.get("reference_number", "")
    notes      = request.form.get("notes", "")

    pay_number = f"PAY-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    execute_db(
        """INSERT INTO payments
           (payment_number, shop_id, payment_type, amount,
            reference_number, status, notes, created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,'RECEIVED',%s,NOW(),NOW())""",
        (pay_number, shop_id, ptype, amount, reference, notes)
    )
    flash(f"Payment {pay_number} recorded successfully.", "success")
    return redirect(url_for("payments"))


# ─────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────
@app.route("/reports")
@login_required
@role_required("ADMIN", "OWNER", "ACCOUNTANT")
def reports():
    # Sales by product
    by_product = query_db(
        """SELECT p.product_name, p.category,
                  COUNT(d.id) as deliveries,
                  SUM(d.delivered_quantity) as units_sold,
                  SUM(i.selling_price * d.delivered_quantity) as revenue,
                  SUM(i.cost_per_unit * d.delivered_quantity) as cost,
                  SUM((i.selling_price-i.cost_per_unit) * d.delivered_quantity) as profit
           FROM deliveries d
           JOIN inventory i ON d.inventory_id = i.id
           JOIN products p ON i.product_id = p.id
           WHERE d.status = 'DELIVERED'
             AND d.created_at >= CURRENT_DATE - INTERVAL '30 days'
           GROUP BY p.id, p.product_name, p.category
           ORDER BY revenue DESC"""
    )

    # Sales by shop
    by_shop = query_db(
        """SELECT rs.shop_name,
                  COUNT(DISTINCT d.id) as deliveries,
                  SUM(d.delivered_quantity) as units_bought,
                  SUM(i.selling_price * d.delivered_quantity) as total_spent
           FROM deliveries d
           JOIN inventory i ON d.inventory_id = i.id
           JOIN delivery_trips dt ON d.trip_id = dt.id
           JOIN retail_shops rs ON d.shop_id = rs.id
           WHERE d.status = 'DELIVERED'
             AND dt.trip_date >= CURRENT_DATE - INTERVAL '30 days'
           GROUP BY rs.id, rs.shop_name
           ORDER BY total_spent DESC"""
    )

    # Salesman performance
    by_salesman = query_db(
        """SELECT up.full_name,
                  COUNT(DISTINCT dt.id) as trips,
                  SUM(dt.cash_collected + dt.digital_collected) as collected,
                  SUM(dt.allowance_amount) as allowance
           FROM delivery_trips dt
           JOIN salesmen s ON dt.salesman_id = s.id
           JOIN users u ON s.user_id = u.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           WHERE dt.trip_date >= CURRENT_DATE - INTERVAL '30 days'
           GROUP BY up.full_name
           ORDER BY collected DESC"""
    )

    # Waste analysis
    waste_analysis = query_db(
        """SELECT p.product_name,
                  SUM(pw.quantity) as total_waste,
                  pw.waste_type,
                  pw.decision
           FROM production_waste pw
           JOIN production_batches pb ON pw.batch_id = pb.id
           JOIN products p ON pb.product_id = p.id
           WHERE pb.production_date >= CURRENT_DATE - INTERVAL '30 days'
           GROUP BY p.product_name, pw.waste_type, pw.decision
           ORDER BY total_waste DESC"""
    )

    return render_template("reports.html",
        user=current_user(),
        by_product=convert_decimals(list(by_product)),
        by_shop=convert_decimals(list(by_shop)),
        by_salesman=convert_decimals(list(by_salesman)),
        waste_analysis=convert_decimals(list(waste_analysis)),
    )


# ─────────────────────────────────────────────
# USER MANAGEMENT (Admin only)
# ─────────────────────────────────────────────
@app.route("/users")
@login_required
@role_required("ADMIN", "OWNER")
def users():
    all_users = query_db(
        """SELECT u.id, u.username, u.email, u.status, u.last_login,
                  r.role_name, up.full_name, up.phone
           FROM users u
           JOIN roles r ON u.role_id = r.id
           LEFT JOIN user_profiles up ON u.id = up.user_id
           ORDER BY r.id, up.full_name"""
    )
    roles = query_db("SELECT id, role_name FROM roles ORDER BY id")

    return render_template("users.html",
        user=current_user(),
        all_users=convert_decimals(list(all_users)),
        roles=convert_decimals(list(roles)),
    )


@app.route("/users/new", methods=["POST"])
@login_required
@role_required("ADMIN", "OWNER")
def new_user():
    email     = request.form.get("email")
    username  = request.form.get("username")
    password  = request.form.get("password")
    role_id   = request.form.get("role_id")
    full_name = request.form.get("full_name")
    phone     = request.form.get("phone", "")

    # Check if user exists
    existing = query_db("SELECT id FROM users WHERE email=%s OR username=%s",
                        (email, username), one=True)
    if existing:
        flash("User with that email/username already exists.", "danger")
        return redirect(url_for("users"))

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode()

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO users (username,email,password_hash,role_id,status,created_at,updated_at)
               VALUES (%s,%s,%s,%s,'ACTIVE',NOW(),NOW()) RETURNING id""",
            (username, email, hashed, role_id)
        )
        user_id = cur.fetchone()[0]
        cur.execute(
            """INSERT INTO user_profiles (user_id,full_name,phone,created_at,updated_at)
               VALUES (%s,%s,%s,NOW(),NOW())""",
            (user_id, full_name, phone)
        )
        conn.commit()
        flash(f"User {full_name} created!", "success")
    except Exception as e:
        conn.rollback()
        flash("Error creating user.", "danger")
    finally:
        conn.close()

    return redirect(url_for("users"))


@app.route("/users/<user_id>/toggle", methods=["POST"])
@login_required
@role_required("ADMIN")
def toggle_user(user_id):
    user = query_db("SELECT status FROM users WHERE id=%s", (user_id,), one=True)
    new_status = "INACTIVE" if user["status"] == "ACTIVE" else "ACTIVE"
    execute_db("UPDATE users SET status=%s, updated_at=NOW() WHERE id=%s",
               (new_status, user_id))
    flash(f"User status set to {new_status}.", "success")
    return redirect(url_for("users"))


# ─────────────────────────────────────────────
# API ENDPOINTS (JSON) - for AJAX/mobile
# ─────────────────────────────────────────────
@app.route("/api/dashboard/stats")
@login_required
def api_dashboard_stats():
    today = date.today()
    sales = query_db(
        """SELECT COALESCE(SUM(i.selling_price * d.delivered_quantity),0) as total
           FROM deliveries d
           JOIN inventory i ON d.inventory_id=i.id
           JOIN delivery_trips dt ON d.trip_id=dt.id
           WHERE dt.trip_date=%s AND d.status='DELIVERED'""",
        (today,), one=True
    )
    return jsonify({"today_sales": convert_decimals(sales["total"]) if sales else 0})


@app.route("/api/inventory/low-stock")
@login_required
def api_low_stock():
    low = query_db(
        """SELECT material_name, current_stock, reorder_level, unit
           FROM raw_materials WHERE current_stock <= reorder_level AND is_active=true"""
    )
    return jsonify({"items": convert_decimals([dict(r) for r in low])})


@app.route("/api/products")
def api_products():
    products = query_db(
        """SELECT p.id, p.product_name, p.pack_size, p.unit_price,
                  COALESCE(SUM(i.quantity_available),0) as stock
           FROM products p
           LEFT JOIN inventory i ON p.id=i.product_id AND i.status='AVAILABLE'
           WHERE p.is_active=true
           GROUP BY p.id"""
    )
    return jsonify({"products": convert_decimals([dict(r) for r in products])})


# ─────────────────────────────────────────────
# DB SETUP ROUTE (first run only)
# ─────────────────────────────────────────────
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Initialize database - run once after deployment."""
    if request.method == "POST":
        token = request.form.get("token")
        if token != os.environ.get("SECRET_KEY", ""):
            return "Unauthorized", 403

        try:
            _run_migrations()
            return "<h2>Database initialized! <a href='/login'>Login</a></h2>"
        except Exception as e:
            return f"<h2>Error: {e}</h2>", 500

    return """
    <h2>Milan Bakery - Database Setup</h2>
    <form method="POST">
        <input type="password" name="token" placeholder="Enter SECRET_KEY to confirm">
        <button type="submit">Initialize Database</button>
    </form>
    """


def _run_migrations():
    """Create all tables and seed initial data."""
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        role_name VARCHAR(50) UNIQUE NOT NULL,
        permissions JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role_id INTEGER NOT NULL REFERENCES roles(id),
        status VARCHAR(20) DEFAULT 'ACTIVE',
        last_login TIMESTAMP,
        reset_token VARCHAR(255),
        reset_token_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_profiles (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name VARCHAR(100),
        phone VARCHAR(15),
        address TEXT,
        city VARCHAR(50),
        state VARCHAR(50),
        pincode VARCHAR(10),
        profile_photo VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS suppliers (
        id SERIAL PRIMARY KEY,
        supplier_name VARCHAR(100) NOT NULL,
        contact_person VARCHAR(100),
        phone VARCHAR(15),
        email VARCHAR(100),
        address TEXT,
        gst_number VARCHAR(20),
        payment_terms VARCHAR(50) DEFAULT 'CASH',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS raw_materials (
        id SERIAL PRIMARY KEY,
        material_name VARCHAR(100) NOT NULL,
        barcode VARCHAR(50) UNIQUE,
        unit VARCHAR(20) NOT NULL DEFAULT 'KG',
        current_stock DECIMAL(10,2) DEFAULT 0,
        reorder_level DECIMAL(10,2) NOT NULL DEFAULT 0,
        cost_per_unit DECIMAL(10,2) NOT NULL DEFAULT 0,
        supplier_id INTEGER REFERENCES suppliers(id),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS raw_material_transactions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        material_id INTEGER NOT NULL REFERENCES raw_materials(id),
        transaction_type VARCHAR(10) NOT NULL,
        quantity DECIMAL(10,2) NOT NULL,
        cost DECIMAL(10,2),
        batch_number VARCHAR(50),
        supplier_id INTEGER REFERENCES suppliers(id),
        reference_type VARCHAR(20),
        reference_id UUID,
        transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
        notes TEXT,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        product_name VARCHAR(100) NOT NULL,
        barcode_prefix VARCHAR(10) UNIQUE,
        category VARCHAR(50) NOT NULL DEFAULT 'OTHER',
        pack_size INTEGER NOT NULL DEFAULT 1,
        unit_price DECIMAL(10,2) NOT NULL DEFAULT 0,
        description TEXT,
        shelf_life_days INTEGER,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS product_recipes (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products(id),
        material_id INTEGER NOT NULL REFERENCES raw_materials(id),
        quantity_required DECIMAL(10,3) NOT NULL,
        unit VARCHAR(20) NOT NULL,
        cost_per_unit DECIMAL(10,2),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(product_id, material_id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_batches (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        batch_number VARCHAR(50) UNIQUE NOT NULL,
        product_id INTEGER NOT NULL REFERENCES products(id),
        planned_quantity INTEGER NOT NULL,
        actual_quantity INTEGER,
        waste_quantity INTEGER DEFAULT 0,
        production_date DATE NOT NULL,
        production_manager_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'PLANNED',
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        total_cost DECIMAL(12,2),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_costs (
        id SERIAL PRIMARY KEY,
        batch_id UUID NOT NULL REFERENCES production_batches(id) ON DELETE CASCADE,
        cost_type VARCHAR(50) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_waste (
        id SERIAL PRIMARY KEY,
        batch_id UUID NOT NULL REFERENCES production_batches(id),
        waste_type VARCHAR(50) NOT NULL DEFAULT 'OTHER',
        quantity INTEGER NOT NULL,
        reason TEXT,
        decision VARCHAR(20) DEFAULT 'PENDING',
        decided_by UUID REFERENCES users(id),
        decided_at TIMESTAMP,
        photos TEXT[],
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS packaging_batches (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        production_batch_id UUID NOT NULL REFERENCES production_batches(id),
        product_id INTEGER NOT NULL REFERENCES products(id),
        pack_size INTEGER NOT NULL,
        packs_created INTEGER NOT NULL,
        individual_units INTEGER DEFAULT 0,
        packaging_cost DECIMAL(10,2) NOT NULL DEFAULT 0,
        packaging_date DATE NOT NULL DEFAULT CURRENT_DATE,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS inventory (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        product_id INTEGER NOT NULL REFERENCES products(id),
        packaging_batch_id UUID REFERENCES packaging_batches(id),
        barcode VARCHAR(100) UNIQUE,
        pack_size INTEGER NOT NULL DEFAULT 1,
        quantity_available INTEGER NOT NULL DEFAULT 0,
        cost_per_unit DECIMAL(10,2) NOT NULL DEFAULT 0,
        selling_price DECIMAL(10,2) NOT NULL DEFAULT 0,
        status VARCHAR(20) DEFAULT 'AVAILABLE',
        location VARCHAR(50),
        expiry_date DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS retail_shops (
        id SERIAL PRIMARY KEY,
        shop_name VARCHAR(100) NOT NULL,
        owner_id UUID REFERENCES users(id),
        contact_person VARCHAR(100),
        phone VARCHAR(15),
        email VARCHAR(100),
        address TEXT,
        city VARCHAR(50),
        state VARCHAR(50),
        pincode VARCHAR(10),
        gps_latitude DECIMAL(10,8),
        gps_longitude DECIMAL(11,8),
        credit_limit DECIMAL(10,2) DEFAULT 0,
        payment_terms VARCHAR(50) DEFAULT 'COD',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS customer_orders (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        order_number VARCHAR(50) UNIQUE NOT NULL,
        shop_id INTEGER NOT NULL REFERENCES retail_shops(id),
        order_date TIMESTAMP DEFAULT NOW(),
        delivery_date DATE NOT NULL,
        preferred_time VARCHAR(20),
        status VARCHAR(20) DEFAULT 'PENDING',
        special_instructions TEXT,
        total_amount DECIMAL(10,2),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS customer_order_items (
        id SERIAL PRIMARY KEY,
        order_id UUID NOT NULL REFERENCES customer_orders(id) ON DELETE CASCADE,
        product_id INTEGER NOT NULL REFERENCES products(id),
        pack_size INTEGER NOT NULL DEFAULT 1,
        quantity INTEGER NOT NULL,
        unit_price DECIMAL(10,2) NOT NULL,
        total_price DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS salesmen (
        id SERIAL PRIMARY KEY,
        user_id UUID UNIQUE NOT NULL REFERENCES users(id),
        employee_code VARCHAR(20) UNIQUE NOT NULL,
        vehicle_number VARCHAR(20),
        daily_allowance DECIMAL(8,2) DEFAULT 500.00,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_trips (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        trip_number VARCHAR(50) UNIQUE NOT NULL,
        salesman_id INTEGER NOT NULL REFERENCES salesmen(id),
        trip_date DATE NOT NULL,
        trip_sequence INTEGER NOT NULL DEFAULT 1,
        vehicle_number VARCHAR(20),
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        allowance_amount DECIMAL(8,2) DEFAULT 500.00,
        status VARCHAR(20) DEFAULT 'PLANNED',
        total_sales DECIMAL(10,2) DEFAULT 0,
        cash_collected DECIMAL(10,2) DEFAULT 0,
        digital_collected DECIMAL(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS trip_assignments (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        trip_id UUID NOT NULL REFERENCES delivery_trips(id) ON DELETE CASCADE,
        inventory_id UUID NOT NULL REFERENCES inventory(id),
        quantity_assigned INTEGER NOT NULL,
        barcode VARCHAR(100),
        status VARCHAR(20) DEFAULT 'ASSIGNED',
        created_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS deliveries (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        trip_id UUID NOT NULL REFERENCES delivery_trips(id),
        shop_id INTEGER NOT NULL REFERENCES retail_shops(id),
        inventory_id UUID NOT NULL REFERENCES inventory(id),
        planned_quantity INTEGER NOT NULL,
        delivered_quantity INTEGER,
        delivery_time TIMESTAMP,
        gps_latitude DECIMAL(10,8),
        gps_longitude DECIMAL(11,8),
        status VARCHAR(20) DEFAULT 'PENDING',
        signature_image TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_returns (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        delivery_id UUID REFERENCES deliveries(id),
        trip_id UUID REFERENCES delivery_trips(id),
        inventory_id UUID NOT NULL REFERENCES inventory(id),
        shop_id INTEGER REFERENCES retail_shops(id),
        quantity_returned INTEGER NOT NULL,
        return_reason VARCHAR(50) DEFAULT 'OTHER',
        return_condition VARCHAR(20) DEFAULT 'GOOD',
        photos TEXT[],
        decision VARCHAR(20) DEFAULT 'PENDING',
        decided_by UUID REFERENCES users(id),
        decided_at TIMESTAMP,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        payment_number VARCHAR(50) UNIQUE NOT NULL,
        shop_id INTEGER NOT NULL REFERENCES retail_shops(id),
        trip_id UUID REFERENCES delivery_trips(id),
        delivery_id UUID REFERENCES deliveries(id),
        payment_type VARCHAR(20) NOT NULL DEFAULT 'CASH',
        amount DECIMAL(10,2) NOT NULL,
        payment_date TIMESTAMP DEFAULT NOW(),
        reference_number VARCHAR(100),
        status VARCHAR(20) DEFAULT 'RECEIVED',
        collected_by INTEGER REFERENCES salesmen(id),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS invoices (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        invoice_number VARCHAR(50) UNIQUE NOT NULL,
        shop_id INTEGER NOT NULL REFERENCES retail_shops(id),
        delivery_id UUID REFERENCES deliveries(id),
        invoice_date DATE NOT NULL DEFAULT CURRENT_DATE,
        due_date DATE NOT NULL,
        subtotal DECIMAL(10,2) NOT NULL,
        gst_percentage DECIMAL(5,2) DEFAULT 5.00,
        gst_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
        total_amount DECIMAL(10,2) NOT NULL,
        amount_paid DECIMAL(10,2) DEFAULT 0,
        balance DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'PENDING',
        pdf_path TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        shop_id INTEGER NOT NULL REFERENCES retail_shops(id),
        delivery_id UUID REFERENCES deliveries(id),
        product_id INTEGER REFERENCES products(id),
        rating INTEGER,
        feedback_type VARCHAR(20) DEFAULT 'OTHER',
        comments TEXT,
        photos TEXT[],
        status VARCHAR(20) DEFAULT 'OPEN',
        resolved_by UUID REFERENCES users(id),
        resolved_at TIMESTAMP,
        resolution_notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""")

    # ── Seed roles ──
    cur.execute("""
    INSERT INTO roles (role_name, permissions) VALUES
      ('ADMIN',              '{"all": true}'),
      ('OWNER',              '{"dashboard":true,"reports":true,"finance":true,"approve_waste":true,"production":true,"inventory":true}'),
      ('PRODUCTION_MANAGER', '{"production":true,"inventory":true,"waste":true,"packaging":true}'),
      ('SALESMAN',           '{"delivery":true,"collect_payment":true,"view_trips":true}'),
      ('RETAIL_SHOP',        '{"order":true,"feedback":true,"view_invoice":true}'),
      ('ACCOUNTANT',         '{"finance":true,"reports":true,"invoices":true,"payments":true}')
    ON CONFLICT (role_name) DO NOTHING
    """)

    # ── Seed admin user ──
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@milanbakery.com")
    admin_pw    = os.environ.get("ADMIN_PASSWORD", "Admin@123")
    hashed      = bcrypt.hashpw(admin_pw.encode(), bcrypt.gensalt(10)).decode()
    cur.execute(
        """INSERT INTO users (username,email,password_hash,role_id,status)
           VALUES ('admin',%s,%s,1,'ACTIVE')
           ON CONFLICT (email) DO NOTHING""",
        (admin_email, hashed)
    )

    # admin profile
    cur.execute("""
    INSERT INTO user_profiles (user_id, full_name, phone)
    SELECT u.id, 'System Admin', '+91 9999999999'
    FROM users u WHERE u.email = %s
    ON CONFLICT (user_id) DO NOTHING""", (admin_email,))

    # ── Seed products ──
    cur.execute("""
    INSERT INTO products (product_name, barcode_prefix, category, pack_size, unit_price, shelf_life_days) VALUES
      ('White Bread 500g',  'BRD',  'BREAD',   30, 950.00,  5),
      ('Brown Toast',       'TST',  'TOAST',   20, 700.00,  7),
      ('Masala Toast',      'MTST', 'TOAST',   25, 850.00,  7),
      ('Kara Biscuit',      'KARA', 'BISCUIT', 50, 1200.00, 30),
      ('Shev Mix',          'SHEV', 'SNACKS',  40, 800.00,  15)
    ON CONFLICT (barcode_prefix) DO NOTHING
    """)

    # ── Seed raw materials ──
    cur.execute("""
    INSERT INTO raw_materials (material_name, barcode, unit, current_stock, reorder_level, cost_per_unit) VALUES
      ('Maida (All Purpose Flour)', 'RM-MAIDA',   'KG',    500, 100, 35.00),
      ('Sugar',                     'RM-SUGAR',   'KG',    200,  50, 45.00),
      ('Yeast',                     'RM-YEAST',   'KG',    3.5,   5, 200.00),
      ('Salt',                      'RM-SALT',    'KG',     50,  10, 15.00),
      ('Butter',                    'RM-BUTTER',  'KG',     30,  10, 400.00),
      ('Packaging Bags (Bread)',     'RM-PKG-BRD', 'UNITS', 5000,1000, 2.00)
    ON CONFLICT (barcode) DO NOTHING
    """)

    # ── Seed supplier ──
    cur.execute("""
    INSERT INTO suppliers (supplier_name, contact_person, phone, address, payment_terms) VALUES
      ('ABC Flour Mills', 'Ramesh Kumar', '+91 9876543210', 'Industrial Area, Bangalore', 'NET30')
    ON CONFLICT DO NOTHING
    """)

    # ── Seed sample shops ──
    cur.execute("""
    INSERT INTO retail_shops (shop_name, contact_person, phone, address, city, state, payment_terms) VALUES
      ('Ramesh Stores',     'Ramesh',   '+91 9876500001', 'MG Road Shop #15',       'Bangalore', 'Karnataka', 'COD'),
      ('Lakshmi Provision', 'Lakshmi',  '+91 9876500002', '2nd Cross Near Bus Stop','Bangalore', 'Karnataka', 'COD'),
      ('Ganesh Traders',    'Ganesh',   '+91 9876500003', 'Main Market Road',        'Bangalore', 'Karnataka', 'COD'),
      ('Krishna Mart',      'Krishna',  '+91 9876500004', 'Main Street Shop #42',    'Bangalore', 'Karnataka', 'COD'),
      ('Sri Sai Stores',    'Sai Kumar','+91 9876500005', 'JP Nagar 5th Phase',      'Bangalore', 'Karnataka', 'COD')
    ON CONFLICT DO NOTHING
    """)

    # ── Seed product recipes (quantity per 1 unit/loaf/pack produced) ──
    cur.execute("""
    INSERT INTO product_recipes (product_id, material_id, quantity_required, unit, cost_per_unit)
    SELECT p.id, rm.id,
      CASE rm.barcode
        WHEN 'RM-MAIDA'   THEN 0.500
        WHEN 'RM-SUGAR'   THEN 0.020
        WHEN 'RM-YEAST'   THEN 0.010
        WHEN 'RM-SALT'    THEN 0.010
        WHEN 'RM-BUTTER'  THEN 0.050
        WHEN 'RM-PKG-BRD' THEN 1.000
      END,
      rm.unit, rm.cost_per_unit
    FROM products p, raw_materials rm
    WHERE p.barcode_prefix = 'BRD'
      AND rm.barcode IN ('RM-MAIDA','RM-SUGAR','RM-YEAST','RM-SALT','RM-BUTTER','RM-PKG-BRD')
    ON CONFLICT DO NOTHING
    """)

    cur.execute("""
    INSERT INTO product_recipes (product_id, material_id, quantity_required, unit, cost_per_unit)
    SELECT p.id, rm.id,
      CASE rm.barcode
        WHEN 'RM-MAIDA'   THEN 0.450
        WHEN 'RM-SUGAR'   THEN 0.015
        WHEN 'RM-YEAST'   THEN 0.008
        WHEN 'RM-SALT'    THEN 0.008
        WHEN 'RM-BUTTER'  THEN 0.040
        WHEN 'RM-PKG-BRD' THEN 1.000
      END,
      rm.unit, rm.cost_per_unit
    FROM products p, raw_materials rm
    WHERE p.barcode_prefix IN ('TST', 'MTST')
      AND rm.barcode IN ('RM-MAIDA','RM-SUGAR','RM-YEAST','RM-SALT','RM-BUTTER','RM-PKG-BRD')
    ON CONFLICT DO NOTHING
    """)

    cur.execute("""
    INSERT INTO product_recipes (product_id, material_id, quantity_required, unit, cost_per_unit)
    SELECT p.id, rm.id,
      CASE rm.barcode
        WHEN 'RM-MAIDA'   THEN 0.300
        WHEN 'RM-SUGAR'   THEN 0.100
        WHEN 'RM-BUTTER'  THEN 0.020
        WHEN 'RM-SALT'    THEN 0.005
        WHEN 'RM-PKG-BRD' THEN 1.000
      END,
      rm.unit, rm.cost_per_unit
    FROM products p, raw_materials rm
    WHERE p.barcode_prefix = 'KARA'
      AND rm.barcode IN ('RM-MAIDA','RM-SUGAR','RM-BUTTER','RM-SALT','RM-PKG-BRD')
    ON CONFLICT DO NOTHING
    """)

    cur.execute("""
    INSERT INTO product_recipes (product_id, material_id, quantity_required, unit, cost_per_unit)
    SELECT p.id, rm.id,
      CASE rm.barcode
        WHEN 'RM-MAIDA'   THEN 0.200
        WHEN 'RM-SALT'    THEN 0.010
        WHEN 'RM-PKG-BRD' THEN 1.000
      END,
      rm.unit, rm.cost_per_unit
    FROM products p, raw_materials rm
    WHERE p.barcode_prefix = 'SHEV'
      AND rm.barcode IN ('RM-MAIDA','RM-SALT','RM-PKG-BRD')
    ON CONFLICT DO NOTHING
    """)

    # ── Seed inventory (sample) ──
    cur.execute("""
    INSERT INTO inventory (product_id, barcode, pack_size, quantity_available, cost_per_unit, selling_price, status, expiry_date)
    SELECT p.id,
           p.barcode_prefix || '-DEMO-' || p.id::text,
           p.pack_size,
           CASE p.id WHEN 1 THEN 45 WHEN 2 THEN 23 WHEN 3 THEN 8 WHEN 4 THEN 30 ELSE 15 END,
           CASE p.id WHEN 1 THEN 805 WHEN 2 THEN 580 WHEN 3 THEN 710 WHEN 4 THEN 1010 ELSE 650 END,
           p.unit_price,
           'AVAILABLE',
           CURRENT_DATE + INTERVAL '5 days'
    FROM products p
    WHERE NOT EXISTS (SELECT 1 FROM inventory WHERE product_id = p.id)
    """)

    # ── Create indexes for performance ──
    cur.execute("CREATE INDEX IF NOT EXISTS idx_batches_date ON production_batches(production_date DESC, status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_batches_product ON production_batches(product_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_date ON deliveries(status, created_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(payment_date DESC, status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inventory_product ON inventory(product_id, status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON customer_orders(status, created_at DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_recipes_product ON product_recipes(product_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_materials_active ON raw_materials(is_active, current_stock)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_waste_pending ON production_waste(decision)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS production_goals (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products(id),
        target_month INTEGER NOT NULL CHECK (target_month BETWEEN 1 AND 12),
        target_year  INTEGER NOT NULL,
        target_quantity INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(product_id, target_month, target_year)
    )""")

    conn.commit()
    print("Milan Bakery DB initialized!")


# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", user=current_user() if "user_id" in session else None), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("404.html", user=current_user() if "user_id" in session else None), 500


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
