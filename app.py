from flask import Flask, render_template, request, redirect, url_for, g, jsonify, send_file
import sqlite3
import os
import json
import csv
import io
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps
from flask import session, flash

app = Flask(__name__)
app.secret_key = 'super_secret_key_neem_impex' # Required for session
DB_NAME = "inventory.db"
UPLOAD_FOLDER = "static/uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # 1. Create Tables if they don't exist
        db.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                pack_size_gm REAL,
                case_size INTEGER,
                pack_size_kg REAL,
                net_weight_case REAL,
                gross_weight_case REAL,
                case_len_inch REAL,
                case_width_inch REAL,
                case_height_inch REAL,
                volume_value REAL, 
                image_path TEXT
            )
        ''')
        db.execute('CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)')
        db.execute('''
            CREATE TABLE IF NOT EXISTS shipments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_name TEXT NOT NULL,
                client_name TEXT,
                container_type INTEGER,
                total_vol REAL,
                total_weight REAL,
                total_cases INTEGER,
                total_expense REAL,
                created_at TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS shipment_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shipment_id INTEGER,
                product_name TEXT,
                quantity INTEGER,
                FOREIGN KEY(shipment_id) REFERENCES shipments(id)
            )
        ''')
        
        # 2. AUTO-MIGRATION: Check if 'total_expense' exists, if not, add it.
        try:
            db.execute("SELECT total_expense FROM shipments LIMIT 1")
        except sqlite3.OperationalError:
            print("⚠️ Updating Database: Adding missing 'total_expense' column...")
            db.execute("ALTER TABLE shipments ADD COLUMN total_expense REAL DEFAULT 0")
            db.commit()
            print("✅ Database Updated Successfully!")

        # 3. AUTO-MIGRATION: Check if 'category' exists, if not, add it.
        try:
            db.execute("SELECT category FROM products LIMIT 1")
        except sqlite3.OperationalError:
            print("⚠️ Updating Database: Adding missing 'category' column...")
            db.execute("ALTER TABLE products ADD COLUMN category TEXT")
            db.commit()
            print("✅ Database Updated Successfully!")

        # 4. Create Users Table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                reset_token TEXT,
                role TEXT DEFAULT 'user',
                access_inventory INTEGER DEFAULT 1,
                access_calculator INTEGER DEFAULT 1
            )
        ''')
        
        # 5. AUTO-MIGRATION: Add new columns to 'users' if they don't exist
        try:
            db.execute("SELECT role FROM users LIMIT 1")
        except sqlite3.OperationalError:
            print("⚠️ Updating Database: Adding missing 'role' and permission columns to users...")
            db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            db.execute("ALTER TABLE users ADD COLUMN access_inventory INTEGER DEFAULT 1")
            db.execute("ALTER TABLE users ADD COLUMN access_calculator INTEGER DEFAULT 1")
            db.commit()
            print("✅ Users Table Updated Successfully!")

        # 6. Create Default Admin User
        # Logic: Check for 'admin@gmail.com'. If not found, check for old 'Shubham' and rename it. If neither, create new.
        
        target_email = "admin@gmail.com"
        
        # Check if old admin exists and migrate
        old_admin = db.execute("SELECT * FROM users WHERE email = 'Shubham'").fetchone()
        if old_admin:
            print("⚠️ Migrating Admin User 'Shubham' to 'admin@gmail.com'...")
            db.execute("UPDATE users SET email = ? WHERE id = ?", (target_email, old_admin['id']))
            db.commit()
        
        # Ensure Admin Exists
        admin = db.execute("SELECT * FROM users WHERE email = ?", (target_email,)).fetchone()
        if not admin:
            hashed_pw = generate_password_hash("Shubham1901")
            db.execute("INSERT INTO users (company_name, email, password_hash, role, access_inventory, access_calculator) VALUES (?, ?, ?, ?, ?, ?)",
                       ("Admin", target_email, hashed_pw, "admin", 1, 1))
            db.commit()
            print(f"✅ Admin User '{target_email}' Created/Verified.")

        db.commit()

# --- ROUTES ---

# --- AUTH & DECORATORS ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        # Check if user has permission for the requested endpoint
        if request.endpoint == 'index' and not g.user['access_inventory']:
             if g.user['access_calculator']:
                 return redirect(url_for('calculator'))
             flash("You do not have access to Inventory.", "error")
             return redirect(url_for('logout'))
             
        if request.endpoint == 'calculator' and not g.user['access_calculator']:
             if g.user['access_inventory']:
                 return redirect(url_for('index'))
             flash("You do not have access to Calculator.", "error")
             return redirect(url_for('index')) # Will cascade to logout check above if stuck

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or g.user['role'] != 'admin':
            flash("Admin access required.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        # If user was deleted but session exists, clear session
        if g.user is None:
            session.clear()

# --- AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip() if request.form.get('email') else ''
        password = request.form.get('password')
        db = get_db()
        # Login by Email ONLY (Company Name is no longer unique)
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            
            # Smart Redirect based on permissions
            role = user['role']
            has_inv = bool(user['access_inventory'])
            has_calc = bool(user['access_calculator'])

            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif has_inv:
                return redirect(url_for('index'))
            elif has_calc:
                return redirect(url_for('calculator'))
            else:
                flash("Your account has no active module access. Please contact Admin.", "error")
                session.clear()
                return redirect(url_for('login'))
                session.clear()
                return redirect(url_for('login'))
        
        flash('Invalid email or password', 'error')
        
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    company_name = "NEEM IMPEX"
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('login')) # Redirect back to login/signup page

    db = get_db()
    try:
        hashed_pw = generate_password_hash(password)
        db.execute("INSERT INTO users (company_name, email, password_hash) VALUES (?, ?, ?)",
                   (company_name, email, hashed_pw))
        db.commit()
        
        # Auto login after signup
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        session.clear()
        session['user_id'] = user['id']
        return redirect(url_for('index'))
    except sqlite3.IntegrityError:
        flash('Email already registered!', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if user:
        token = secrets.token_urlsafe(16)
        db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user['id']))
        db.commit()
        # SIMULATION: Print token to console
        print(f"-------------\nPASSWORD RESET LINK for {email}:\nhttp://localhost:5000/reset_password/{token}\n-------------")
        flash('Reset link sent to your email (Check Server Console for Simulation)', 'success')
    else:
        flash('Email not found', 'error')
        
    return redirect(url_for('login'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()
    
    if not user:
        flash('Invalid or expired token', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)
        db.execute("UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?", (hashed_pw, user['id']))
        db.commit()
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))
        
        flash('Invalid or expired token', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)
        db.execute("UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?", (hashed_pw, user['id']))
        db.commit()
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('login.html', reset_token=token) # Reuse login template for reset UI if possible, or create simple one

# --- ADMIN ROUTES ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM users WHERE role != 'admin' ORDER BY id DESC").fetchall()
    return render_template('admin.html', users=users)

@app.route('/admin/update_permissions', methods=['POST'])
@admin_required
def update_permissions():
    user_id = request.form.get('user_id')
    access_inventory = 1 if request.form.get('access_inventory') else 0
    access_calculator = 1 if request.form.get('access_calculator') else 0
    
    db = get_db()
    db.execute("UPDATE users SET access_inventory = ?, access_calculator = ? WHERE id = ?", 
               (access_inventory, access_calculator, user_id))
    db.commit()
    
    flash("Permissions updated successfully.", "success")
    return redirect(url_for('admin_dashboard'))

# Route for deleting users
@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    user_id = request.form.get('user_id')
    db = get_db()
    
    # Prevent deleting self (just in case)
    if int(user_id) == session.get('user_id'):
       flash("Cannot delete your own admin account.", "error")
       return redirect(url_for('admin_dashboard'))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))


# --- ROUTES ---

@app.route('/')
@login_required
def index():
    db = get_db()
    cursor = db.execute("SELECT * FROM products ORDER BY id DESC")
    products = [dict(row) for row in cursor.fetchall()]
    return render_template('index.html', products=products)

@app.route('/calculator')
@login_required
def calculator():
    db = get_db()
    clients = db.execute("SELECT * FROM clients ORDER BY name").fetchall()
    products_cursor = db.execute("SELECT * FROM products ORDER BY name")
    products_list = [dict(row) for row in products_cursor.fetchall()]
    shipments = db.execute("SELECT * FROM shipments ORDER BY id DESC").fetchall()
    return render_template('calculator.html', clients=clients, products_json=json.dumps(products_list), shipments=shipments, products=products_list)

# --- BULK IMPORT / EXPORT ROUTES ---

@app.route('/download_template')
@login_required
def download_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Product Name', 'Pack Size (Gm)', 'Case Size', 'Gross Weight (Kg)', 'L (Inch)', 'W (Inch)', 'H (Inch)'])
    writer.writerow(['Example Product', '500', '24', '12.5', '18', '12', '10'])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='inventory_template.csv')

@app.route('/import_inventory', methods=['POST'])
@login_required
def import_inventory():
    if 'csv_file' not in request.files: return "No file uploaded", 400
    file = request.files['csv_file']
    if file.filename == '': return "No file selected", 400
    if file:
        try:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            next(csv_input) 
            db = get_db()
            for row in csv_input:
                if len(row) < 7: continue
                name = row[0]
                pack_gm = float(row[1] or 0)
                case_size = int(row[2] or 0)
                gross_wt = float(row[3] or 0)
                l = float(row[4] or 0)
                w = float(row[5] or 0)
                h = float(row[6] or 0)
                pack_kg = pack_gm / 1000
                net_wt = pack_kg * case_size
                vol = (l * w * h) / 1728
                db.execute('''INSERT INTO products (name, pack_size_gm, case_size, pack_size_kg, net_weight_case, gross_weight_case, case_len_inch, case_width_inch, case_height_inch, volume_value, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (name, pack_gm, case_size, pack_kg, net_wt, gross_wt, l, w, h, vol, ""))
            db.commit()
            return redirect(url_for('index'))
        except Exception as e: return f"Error processing CSV: {str(e)}", 500

# --- API ROUTES ---

@app.route('/api/add_client', methods=['POST'])
def api_add_client():
    data = request.get_json()
    name = data.get('name')
    if not name: return jsonify({'success': False, 'error': 'Name required'})
    db = get_db()
    try:
        db.execute("INSERT INTO clients (name) VALUES (?)", (name,))
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return jsonify({'success': True, 'id': new_id, 'name': name})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Client already exists'})

@app.route('/api/delete_client', methods=['POST'])
def api_delete_client():
    data = request.get_json()
    db = get_db()
    db.execute("DELETE FROM clients WHERE id = ?", (data.get('id'),))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/delete_shipment', methods=['POST'])
def api_delete_shipment():
    data = request.get_json()
    shipment_id = data.get('id')
    db = get_db()
    db.execute("DELETE FROM shipment_items WHERE shipment_id = ?", (shipment_id,))
    db.execute("DELETE FROM shipments WHERE id = ?", (shipment_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/save_container', methods=['POST'])
def api_save_container():
    data = request.get_json()
    db = get_db()
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    cursor = db.execute('''
        INSERT INTO shipments (container_name, client_name, container_type, total_vol, total_weight, total_cases, total_expense, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (data['container_name'], data['client_name'], data['container_type'], 
          data['total_vol'], data['total_weight'], data['total_cases'], data.get('total_expense', 0), date_str))
    shipment_id = cursor.lastrowid
    for item in data['items']:
        db.execute("INSERT INTO shipment_items (shipment_id, product_name, quantity) VALUES (?, ?, ?)",
                   (shipment_id, item['name'], item['qty']))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/get_shipment/<int:shipment_id>')
def api_get_shipment(shipment_id):
    db = get_db()
    shipment = db.execute("SELECT * FROM shipments WHERE id = ?", (shipment_id,)).fetchone()
    items = db.execute("SELECT * FROM shipment_items WHERE shipment_id = ?", (shipment_id,)).fetchall()
    return jsonify({'success': True, 'shipment': dict(shipment), 'items': [dict(row) for row in items]})

@app.route('/api/update_container', methods=['POST'])
def api_update_container():
    data = request.get_json()
    db = get_db()
    shipment_id = data['shipment_id']
    db.execute('''
        UPDATE shipments SET container_name=?, client_name=?, container_type=?, 
        total_vol=?, total_weight=?, total_cases=?, total_expense=? WHERE id=?
    ''', (data['container_name'], data['client_name'], data['container_type'], 
          data['total_vol'], data['total_weight'], data['total_cases'], data.get('total_expense', 0), shipment_id))
    db.execute("DELETE FROM shipment_items WHERE shipment_id = ?", (shipment_id,))
    for item in data['items']:
        db.execute("INSERT INTO shipment_items (shipment_id, product_name, quantity) VALUES (?, ?, ?)",
                   (shipment_id, item['name'], item['qty']))
    db.commit()
    return jsonify({'success': True})

# --- STANDARD FORM ROUTES ---
@app.route('/add', methods=['POST'])
@login_required
def add_product():
    name = request.form['name']
    category = request.form.get('category', '')
    pack_size_gm = float(request.form['pack_size_gm'] or 0)
    case_size = int(request.form['case_size'] or 0)
    gross_weight_case = float(request.form['gross_weight_case'] or 0)
    case_len = float(request.form['case_len'] or 0)
    case_width = float(request.form['case_width'] or 0)
    case_height = float(request.form['case_height'] or 0)
    pack_size_kg = pack_size_gm / 1000
    net_weight_case = pack_size_kg * case_size
    volume_value = (case_len * case_width * case_height) / 1728
    image_path = ""
    if 'image_file' in request.files:
        file = request.files['image_file']
        if file.filename != '':
            filename = f"{name.replace(' ', '_')}_{file.filename}"
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            image_path = filename
    db = get_db()
    
    # Ensure category column exists (simple migration check)
    try:
        db.execute("SELECT category FROM products LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE products ADD COLUMN category TEXT")
        db.commit()

    db.execute('''INSERT INTO products (name, category, pack_size_gm, case_size, pack_size_kg, net_weight_case, gross_weight_case, case_len_inch, case_width_inch, case_height_inch, volume_value, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (name, category, pack_size_gm, case_size, pack_size_kg, net_weight_case, gross_weight_case, case_len, case_width, case_height, volume_value, image_path))
    db.commit()
    return redirect(url_for('index'))

@app.route('/api/update_product', methods=['POST'])
def api_update_product():
    data = request.get_json()
    try:
        pid = data.get('id')
        name = data.get('name')
        category = data.get('category', '')
        pack_gm = float(data.get('pack_size_gm') or 0)
        case_size = int(data.get('case_size') or 0)
        gross_wt = float(data.get('gross_weight_case') or 0)
        # Dimensions
        l = float(data.get('case_len_inch') or 0)
        w = float(data.get('case_width_inch') or 0)
        h = float(data.get('case_height_inch') or 0)
        
        # Calculations
        pack_kg = pack_gm / 1000
        net_wt = pack_kg * case_size
        vol = (l * w * h) / 1728
        
        db = get_db()
        
        # FAIL-SAFE: Ensure category column exists
        try:
            db.execute("SELECT category FROM products LIMIT 1")
        except sqlite3.OperationalError:
            db.execute("ALTER TABLE products ADD COLUMN category TEXT")
            db.commit()
            
        db.execute('''UPDATE products SET name=?, category=?, pack_size_gm=?, case_size=?, pack_size_kg=?, net_weight_case=?, gross_weight_case=?, case_len_inch=?, case_width_inch=?, case_height_inch=?, volume_value=? WHERE id=?''', 
                   (name, category, pack_gm, case_size, pack_kg, net_wt, gross_wt, l, w, h, vol, pid))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/update', methods=['POST'])
@login_required
def update_products():
    db = get_db()
    ids = request.form.getlist('id')
    names = request.form.getlist('name')
    categories = request.form.getlist('category')
    pack_gms = request.form.getlist('pack_size_gm')
    case_sizes = request.form.getlist('case_size')
    gross_wts = request.form.getlist('gross_weight_case')
    lens = request.form.getlist('case_len_inch')
    widths = request.form.getlist('case_width_inch')
    heights = request.form.getlist('case_height_inch')
    
    # Ensure category column exists on update too if needed
    try:
        db.execute("SELECT category FROM products LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE products ADD COLUMN category TEXT")
        db.commit()

    for i in range(len(ids)):
        p_gm = float(pack_gms[i] or 0)
        c_size = int(case_sizes[i] or 0)
        pk_kg = p_gm / 1000
        net_wt = pk_kg * c_size
        l = float(lens[i] or 0)
        w = float(widths[i] or 0)
        h = float(heights[i] or 0)
        vol = (l * w * h) / 1728
        cat = categories[i] if i < len(categories) else ""
        db.execute('''UPDATE products SET name=?, category=?, pack_size_gm=?, case_size=?, pack_size_kg=?, net_weight_case=?, gross_weight_case=?, case_len_inch=?, case_width_inch=?, case_height_inch=?, volume_value=? WHERE id=?''', (names[i], cat, p_gm, c_size, pk_kg, net_wt, gross_wts[i], l, w, h, vol, ids[i]))
    db.commit()
    return redirect(url_for('index'))

@app.route('/delete', methods=['POST'])
@login_required
def delete_products():
    db = get_db()
    ids_to_delete = request.form.getlist('delete_id')
    for pid in ids_to_delete:
        db.execute("DELETE FROM products WHERE id = ?", (pid,))
    db.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, use_reloader=False)