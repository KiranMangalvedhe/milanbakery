# 🍞 Milan Bakery Management System

**Flask + Neon PostgreSQL + Vercel (Free Tier)**

---

## 🚀 Live Demo Setup (10 minutes)

### Step 1: Get Neon Database (Free)

1. Go to **https://neon.tech** and create a free account
2. Create a new project: `milan-bakery`
3. Copy the **connection string** (looks like):
   ```
   postgresql://username:password@ep-xxx-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```

---

### Step 2: Deploy to Vercel (Free)

1. Push this repo to **GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Milan Bakery initial commit"
   git remote add origin https://github.com/yourusername/milan-bakery.git
   git push -u origin main
   ```

2. Go to **https://vercel.com** → New Project → Import your repo

3. Set **Environment Variables** in Vercel:
   ```
   DATABASE_URL = postgresql://...your-neon-connection-string...
   SECRET_KEY   = milan-bakery-super-secret-key-2025
   ADMIN_EMAIL  = admin@milanbakery.com
   ADMIN_PASSWORD = Admin@123
   ```

4. Click **Deploy** ✅

---

### Step 3: Initialize Database (One Time)

After deployment, go to:
```
https://your-app.vercel.app/setup
```
Enter your `SECRET_KEY` to initialize the database.

---

### Step 4: Login

```
URL:      https://your-app.vercel.app/login
Email:    admin@milanbakery.com
Password: Admin@123
```

**Shop Portal** (no login needed):
```
https://your-app.vercel.app/shop
```

---

## 🏃 Local Development

```bash
# 1. Clone repo
git clone https://github.com/yourusername/milan-bakery.git
cd milan-bakery

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate    # Linux/Mac
venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and configure environment
cp .env.example .env
# Edit .env with your Neon DATABASE_URL and SECRET_KEY

# 5. Run locally
python api/index.py

# 6. Open browser
# http://localhost:5000/setup   (first time - initialize DB)
# http://localhost:5000/login
```

---

## 📂 Project Structure

```
milan-bakery/
├── api/
│   └── index.py          # Main Flask app (all routes + DB logic)
├── templates/
│   ├── base.html         # Sidebar layout
│   ├── login.html        # Login page
│   ├── dashboard.html    # Owner dashboard
│   ├── production.html   # Production management
│   ├── inventory.html    # Inventory tracking
│   ├── delivery.html     # Delivery trips
│   ├── orders.html       # Customer orders
│   ├── payments.html     # Payment tracking
│   ├── reports.html      # Analytics reports
│   ├── users.html        # User management
│   ├── shop_portal.html  # Public shop ordering
│   ├── order_detail.html
│   └── 404.html
├── static/               # CSS / JS (Bootstrap via CDN)
├── requirements.txt
├── vercel.json           # Vercel deployment config
└── .env.example
```

---

## 👥 User Roles

| Role | Access |
|------|--------|
| **ADMIN** | Full system access |
| **OWNER** | Dashboard, production, reports, waste approval |
| **PRODUCTION_MANAGER** | Production, inventory, waste |
| **SALESMAN** | Delivery trips only |
| **RETAIL_SHOP** | Shop portal (place orders) |
| **ACCOUNTANT** | Finance, payments, reports |

---

## 🔗 Key URLs

| Page | URL |
|------|-----|
| Login | `/login` |
| Dashboard | `/dashboard` |
| Production | `/production` |
| Inventory | `/inventory` |
| Delivery | `/delivery` |
| Orders | `/orders` |
| Payments | `/payments` |
| Reports | `/reports` |
| Users | `/users` |
| Shop Portal | `/shop` (public) |
| DB Setup | `/setup` (one time) |
| Health | `/api/products` |

---

## 💰 Hosting Cost

| Service | Plan | Cost |
|---------|------|------|
| **Vercel** | Hobby (Free) | ₹0/month |
| **Neon** | Free tier | ₹0/month |
| **Total** | | **₹0/month** |

**Free tier limits**:
- Vercel: 100 GB bandwidth, unlimited projects
- Neon: 512 MB database, 190 compute hours/month

**When to upgrade**:
- Database > 400 MB → Neon Pro ($19/month)
- High traffic → Vercel Pro ($20/month)

---

## 📦 Dependencies

```
Flask==3.0.3              # Web framework
Flask-Login==0.6.3        # Session management
psycopg2-binary==2.9.9    # PostgreSQL driver for Neon
python-dotenv==1.0.1      # Environment variables
bcrypt==4.1.3             # Password hashing
qrcode[pil]==7.4.2        # Barcode/QR generation
reportlab==4.2.2          # PDF invoice generation
python-dateutil==2.9.0    # Date utilities
```

---

## 🔧 Troubleshooting

**"DATABASE_URL not set" error**:
- Check Vercel environment variables
- Ensure Neon connection string includes `?sslmode=require`

**"Table does not exist" error**:
- Run database setup at `/setup`

**Login fails**:
- Check admin email/password match `.env`
- Re-run `/setup` if needed

**Vercel build fails**:
- Check `requirements.txt` is in root
- Check `vercel.json` routes are correct

---

## 🗺️ Next Steps (Phase 2)

- [ ] Barcode generation for products
- [ ] PDF invoice download
- [ ] WhatsApp order notifications
- [ ] GPS delivery tracking
- [ ] Mobile PWA enhancements
- [ ] Multi-language support (Kannada/Hindi)

---

**Built with ❤️ for Milan Bakery**
