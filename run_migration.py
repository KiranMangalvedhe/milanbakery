"""Run only the missing production_goals table migration."""
import os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from dotenv import load_dotenv
load_dotenv()

import psycopg2

db_url = os.environ.get("DATABASE_URL")
if not db_url:
    print("ERROR: DATABASE_URL not set")
    sys.exit(1)

conn = psycopg2.connect(db_url)
cur  = conn.cursor()

print("Creating production_goals table...")
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
)
""")

print("Creating email index...")
cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

print("Seeding product recipes if missing...")
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

conn.commit()
conn.close()
print("Migration complete!")
