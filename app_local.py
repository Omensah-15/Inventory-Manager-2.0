"""
InvyPro - Professional Inventory Management System
SQLite Edition
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
import pandas as pd
import streamlit as st
import altair as alt

# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    """Application Configuration"""
    DB_FILE = "invypro.db"
    APP_CONFIG = {
        'session_timeout': 3600,
        'max_login_attempts': 5,
        'lockout_minutes': 15,
        'default_currency': 'USD',
        'default_timezone': 'UTC'
    }

config = Config()

# ============================================================================
# STREAMLIT PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="InvyPro Inventory Manager",
    page_icon=":package:",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS
# ============================================================================
st.markdown("""
<style>
    /* Main Theme */
    :root {
        --primary: #2563eb;
        --primary-dark: #1d4ed8;
        --secondary: #64748b;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --light: #f8fafc;
        --dark: #1e293b;
        --border: #e2e8f0;
    }
    
    /* Typography */
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: var(--primary);
        margin-bottom: 1.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid var(--border);
    }
    
    .section-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--dark);
        margin: 1.5rem 0 1rem 0;
    }
    
    /* Cards */
    .metric-card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        border: 1px solid var(--border);
        transition: transform 0.2s, box-shadow 0.2s;
        height: 100%;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
    }
    
    .metric-title {
        font-size: 0.9rem;
        font-weight: 500;
        color: var(--secondary);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.5rem;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary);
        margin: 0.5rem 0;
        line-height: 1.2;
    }
    
    .metric-subtitle {
        font-size: 0.85rem;
        color: var(--secondary);
        margin-top: 0.5rem;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 500;
        padding: 0.5rem 1rem;
        transition: all 0.2s;
    }
    
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    /* Forms */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > select,
    .stTextArea > div > div > textarea {
        border-radius: 6px;
        border: 1px solid var(--border) !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stNumberInput > div > div > input:focus,
    .stSelectbox > div > div > select:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 1px var(--primary) !important;
    }
    
    /* Data Tables */
    .dataframe {
        border-radius: 8px;
        border: 1px solid var(--border) !important;
    }
    
    .dataframe th {
        background-color: #f8fafc !important;
        font-weight: 600 !important;
    }
    
    /* Badges */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .badge-success {
        background-color: #d1fae5;
        color: #065f46;
    }
    
    .badge-warning {
        background-color: #fef3c7;
        color: #92400e;
    }
    
    .badge-danger {
        background-color: #fee2e2;
        color: #991b1b;
    }
    
    /* Sidebar */
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%);
        border-right: 1px solid var(--border);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 12px 24px;
    }
    
    /* Alerts */
    .stAlert {
        border-radius: 8px;
        border: 1px solid var(--border);
    }
    
    /* Divider */
    hr {
        margin: 2rem 0;
        border: none;
        border-top: 1px solid var(--border);
    }
    
    /* Layout Spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Success/Error Messages */
    .stSuccess {
        background-color: #d1fae5 !important;
        color: #065f46 !important;
        border-color: #a7f3d0 !important;
    }
    
    .stError {
        background-color: #fee2e2 !important;
        color: #991b1b !important;
        border-color: #fecaca !important;
    }
    
    .stWarning {
        background-color: #fef3c7 !important;
        color: #92400e !important;
        border-color: #fde68a !important;
    }
    
    .stInfo {
        background-color: #dbeafe !important;
        color: #1e40af !important;
        border-color: #bfdbfe !important;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# DATABASE MANAGEMENT (SQLite)
# ============================================================================
class Database:
    """SQLite database manager"""
    
    @staticmethod
    def get_connection():
        """Get database connection"""
        conn = sqlite3.connect(config.DB_FILE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    @staticmethod
    def test_connection():
        """Test database connection"""
        try:
            conn = Database.get_connection()
            conn.execute("SELECT 1")
            conn.close()
            return True
        except:
            return False

@contextmanager
def db_session():
    """Context manager for database transactions"""
    conn = Database.get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def execute_query(query: str, params: Tuple = (), fetch: bool = False):
    """Execute SQL query with parameters"""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        if fetch:
            return cur.fetchall()
        return cur.rowcount

def fetch_dataframe(query: str, params: Tuple = ()) -> pd.DataFrame:
    """Fetch query results as pandas DataFrame"""
    with db_session() as conn:
        return pd.read_sql_query(query, conn, params=params)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================
def initialize_database():
    """Initialize database schema"""
    schema_queries = [
        # Users table
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            organization TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        """,
        
        # Products table
        """
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            sku TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            supplier TEXT,
            unit TEXT DEFAULT 'pcs',
            cost_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            quantity INTEGER DEFAULT 0,
            min_quantity INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 0,
            location TEXT,
            barcode TEXT,
            notes TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, sku)
        );
        """,
        
        # Transactions table
        """
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL DEFAULT 0,
            total_amount REAL DEFAULT 0,
            reference TEXT,
            notes TEXT,
            status TEXT DEFAULT 'completed',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (product_id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users (user_id),
            CHECK (type IN ('sale', 'purchase', 'adjustment', 'transfer')),
            CHECK (status IN ('pending', 'completed', 'cancelled'))
        );
        """,
        
        # Suppliers table
        """
        CREATE TABLE IF NOT EXISTS suppliers (
            supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            name TEXT NOT NULL,
            contact_person TEXT,
            email TEXT,
            phone TEXT,
            address TEXT,
            payment_terms TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, name)
        );
        """,
        
        # Activity logs
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        );
        """,
        
        # Create indexes
        "CREATE INDEX IF NOT EXISTS idx_products_org ON products(organization);",
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_org ON transactions(organization);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at);"
    ]
    
    try:
        with db_session() as conn:
            cur = conn.cursor()
            for query in schema_queries:
                try:
                    cur.execute(query)
                except Exception as e:
                    # Silently ignore if tables already exist
                    if "already exists" not in str(e):
                        print(f"Schema note: {str(e)}")
        
        # Create default admin user
        create_default_admin()
        return True
    except Exception as e:
        st.error(f"Database initialization failed: {str(e)}")
        return False

def create_default_admin():
    """Create default admin user if no users exist"""
    try:
        result = execute_query("SELECT COUNT(*) as count FROM users;", fetch=True)
        if result and result[0][0] == 0:
            username = "admin"
            password = "admin123"
            organization = "Default Organization"
            
            salt = secrets.token_hex(32)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            ).hex()
            
            execute_query(
                """
                INSERT INTO users (username, password_hash, salt, organization, role)
                VALUES (?, ?, ?, ?, 'admin')
                """,
                (username, password_hash, salt, organization)
            )
            
            print("Created default admin user: admin / admin123")
    except Exception as e:
        print(f"Note: {str(e)}")

# ============================================================================
# SECURITY & AUTHENTICATION
# ============================================================================
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password using PBKDF2"""
    if salt is None:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return h, salt

def verify_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    """Verify password against stored hash"""
    computed, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(computed, stored_hash)

def register_user(username: str, email: str, password: str, organization: str):
    """Register new user"""
    username = username.strip().lower()
    organization = organization.strip()
    email = email.strip().lower() if email else None
    
    if not username or not password or not organization:
        return {"success": False, "message": "Username, password and organization are required"}
    
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters"}
    
    password_hash, salt = hash_password(password)
    
    try:
        execute_query(
            """
            INSERT INTO users (username, email, password_hash, salt, organization, role)
            VALUES (?, ?, ?, ?, ?, 'admin')
            """,
            (username, email, password_hash, salt, organization)
        )
        
        log_activity(
            user_id=None,
            action="user_registration",
            details=f"New user registered: {username} for {organization}"
        )
        
        return {"success": True, "message": "Account created successfully"}
        
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: users.username" in str(e):
            return {"success": False, "message": "Username already exists"}
        else:
            return {"success": False, "message": "Registration failed"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def authenticate_user(username: str, password: str):
    """Authenticate user"""
    username = username.strip().lower()
    
    if not username or not password:
        return {"success": False, "message": "Username and password required"}
    
    try:
        result = execute_query(
            "SELECT user_id, username, password_hash, salt, organization, role, is_active FROM users WHERE username = ?",
            (username,),
            fetch=True
        )
        
        if not result:
            return {"success": False, "message": "Invalid credentials"}
        
        user = result[0]
        
        if user[6] != 1:  # is_active check
            return {"success": False, "message": "Account is inactive"}
        
        if verify_password(user[2], user[3], password):
            # Update last login
            execute_query(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user[0],)
            )
            
            log_activity(
                user_id=user[0],
                action="user_login",
                details=f"User logged in: {username}"
            )
            
            return {
                "success": True,
                "message": "Login successful",
                "user": {
                    'id': user[0],
                    'username': user[1],
                    'organization': user[4],
                    'role': user[5]
                }
            }
        else:
            return {"success": False, "message": "Invalid credentials"}
            
    except Exception as e:
        return {"success": False, "message": f"Authentication error: {str(e)}"}

def log_activity(user_id: Optional[int] = None, action: str = "", details: str = ""):
    """Log user activity"""
    try:
        execute_query(
            """
            INSERT INTO activity_logs (organization, user_id, action, details)
            VALUES (?, ?, ?, ?)
            """,
            (
                st.session_state.get('organization', 'PUBLIC'),
                user_id,
                action,
                details
            )
        )
    except:
        pass  # Silently fail if logging fails

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================
def initialize_session():
    """Initialize session state"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.organization = None
        st.session_state.role = None
        st.session_state.currency = config.APP_CONFIG['default_currency']
        st.session_state.timezone = config.APP_CONFIG['default_timezone']
        st.session_state.page = "Dashboard"
        st.session_state.login_attempts = {}

initialize_session()

def login_user(user_data: dict):
    """Login user and update session"""
    st.session_state.authenticated = True
    st.session_state.user_id = user_data['id']
    st.session_state.username = user_data['username']
    st.session_state.organization = user_data['organization']
    st.session_state.role = user_data['role']
    st.rerun()

def logout_user():
    """Logout user and clear session"""
    if st.session_state.authenticated:
        log_activity(
            user_id=st.session_state.user_id,
            action="user_logout",
            details="User logged out"
        )
    
    # Clear session but keep preferences
    currency = st.session_state.get('currency', 'USD')
    timezone = st.session_state.get('timezone', 'UTC')
    
    keys = list(st.session_state.keys())
    for key in keys:
        del st.session_state[key]
    
    # Restore preferences
    st.session_state.currency = currency
    st.session_state.timezone = timezone
    st.session_state.authenticated = False
    st.session_state.page = "Dashboard"
    st.rerun()

# ============================================================================
# DATA MANAGEMENT
# ============================================================================
def get_current_organization():
    """Get current organization"""
    return st.session_state.organization if st.session_state.authenticated else None

def get_products(search: str = "", page: int = 1, page_size: int = 50):
    """Get products for current organization"""
    org = get_current_organization()
    if not org:
        return pd.DataFrame()
    
    offset = (page - 1) * page_size
    
    query = """
        SELECT 
            product_id, sku, name, description, category, supplier,
            unit, cost_price, sell_price, quantity, min_quantity,
            reorder_level, location, barcode, notes, is_active,
            created_at, updated_at
        FROM products 
        WHERE organization = ?
    """
    
    params = [org]
    
    if search:
        query += " AND (sku LIKE ? OR name LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    
    query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    
    return fetch_dataframe(query, tuple(params))

def add_product(product_data: dict):
    """Add new product"""
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
        execute_query(
            """
            INSERT INTO products (
                organization, sku, name, description, category, supplier,
                unit, cost_price, sell_price, quantity, min_quantity,
                reorder_level, location, barcode, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org,
                product_data['sku'],
                product_data['name'],
                product_data['description'],
                product_data['category'],
                product_data['supplier'],
                product_data['unit'],
                product_data['cost_price'],
                product_data['sell_price'],
                product_data['quantity'],
                product_data['min_quantity'],
                product_data['reorder_level'],
                product_data['location'],
                product_data['barcode'],
                product_data['notes']
            )
        )
        
        log_activity(
            user_id=st.session_state.user_id,
            action="product_added",
            details=f"Added product: {product_data['name']} ({product_data['sku']})"
        )
        
        return {"success": True, "message": "Product added successfully"}
        
    except sqlite3.IntegrityError:
        return {"success": False, "message": "SKU already exists"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def update_product(product_id: int, product_data: dict):
    """Update existing product"""
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
        execute_query(
            """
            UPDATE products SET
                name = ?, description = ?, category = ?, supplier = ?,
                unit = ?, cost_price = ?, sell_price = ?, quantity = ?,
                min_quantity = ?, reorder_level = ?, location = ?,
                barcode = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE product_id = ? AND organization = ?
            """,
            (
                product_data['name'],
                product_data['description'],
                product_data['category'],
                product_data['supplier'],
                product_data['unit'],
                product_data['cost_price'],
                product_data['sell_price'],
                product_data['quantity'],
                product_data['min_quantity'],
                product_data['reorder_level'],
                product_data['location'],
                product_data['barcode'],
                product_data['notes'],
                product_id,
                org
            )
        )
        
        log_activity(
            user_id=st.session_state.user_id,
            action="product_updated",
            details=f"Updated product: {product_data['name']} (ID: {product_id})"
        )
        
        return {"success": True, "message": "Product updated successfully"}
        
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def delete_product(product_id: int):
    """Delete product"""
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
        # Get product name before deletion for logging
        result = execute_query(
            "SELECT name FROM products WHERE product_id = ? AND organization = ?",
            (product_id, org),
            fetch=True
        )
        
        product_name = result[0][0] if result else "Unknown"
        
        execute_query(
            "DELETE FROM products WHERE product_id = ? AND organization = ?",
            (product_id, org)
        )
        
        log_activity(
            user_id=st.session_state.user_id,
            action="product_deleted",
            details=f"Deleted product: {product_name} (ID: {product_id})"
        )
        
        return {"success": True, "message": "Product deleted successfully"}
        
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def get_key_metrics():
    """Calculate key performance indicators"""
    org = get_current_organization()
    if not org:
        return {}
    
    try:
        # Total products
        total_df = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ?",
            (org,)
        )
        total_products = total_df.iloc[0]['count'] if not total_df.empty else 0
        
        # Stock value
        value_df = fetch_dataframe(
            "SELECT SUM(quantity * cost_price) as value FROM products WHERE organization = ?",
            (org,)
        )
        stock_value = value_df.iloc[0]['value'] if not value_df.empty else 0
        
        # Low stock items
        low_df = fetch_dataframe(
            """
            SELECT COUNT(*) as count 
            FROM products 
            WHERE organization = ? AND quantity <= reorder_level AND quantity > 0
            """,
            (org,)
        )
        low_stock = low_df.iloc[0]['count'] if not low_df.empty else 0
        
        # Out of stock items
        out_df = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ? AND quantity = 0",
            (org,)
        )
        out_of_stock = out_df.iloc[0]['count'] if not out_df.empty else 0
        
        # Total value of sales (last 30 days)
        sales_df = fetch_dataframe(
            """
            SELECT COALESCE(SUM(total_amount), 0) as sales
            FROM transactions 
            WHERE organization = ? 
                AND type = 'sale' 
                AND date(created_at) >= date('now', '-30 days')
            """,
            (org,)
        )
        monthly_sales = sales_df.iloc[0]['sales'] if not sales_df.empty else 0
        
        return {
            'total_products': total_products,
            'stock_value': f"{st.session_state.currency} {stock_value:,.2f}",
            'low_stock': low_stock,
            'out_of_stock': out_of_stock,
            'monthly_sales': f"{st.session_state.currency} {monthly_sales:,.2f}"
        }
    except Exception as e:
        print(f"Metrics error: {str(e)}")
        return {}

# ============================================================================
# UI COMPONENTS
# ============================================================================
def render_sidebar():
    """Render sidebar navigation"""
    with st.sidebar:
        st.markdown("## InvyPro")
        st.markdown("*Professional Inventory Management*")
        st.markdown("---")
        
        if not st.session_state.authenticated:
            # Login/Signup Forms
            tab_login, tab_signup = st.tabs(["Login", "Sign Up"])
            
            with tab_login:
                st.subheader("Login")
                login_username = st.text_input("Username", key="login_username")
                login_password = st.text_input("Password", type="password", key="login_password")
                
                if st.button("Login", type="primary", use_container_width=True):
                    result = authenticate_user(login_username, login_password)
                    if result['success']:
                        login_user(result['user'])
                        st.success(result['message'])
                    else:
                        st.error(result['message'])
            
            with tab_signup:
                st.subheader("Create Account")
                signup_username = st.text_input("Choose Username", key="signup_username")
                signup_email = st.text_input("Email (Optional)", key="signup_email")
                signup_org = st.text_input("Organization Name", key="signup_org")
                signup_password = st.text_input("Password", type="password", key="signup_password")
                signup_confirm = st.text_input("Confirm Password", type="password", key="signup_confirm")
                
                if st.button("Create Account", use_container_width=True):
                    if signup_password != signup_confirm:
                        st.error("Passwords do not match")
                    else:
                        result = register_user(signup_username, signup_email, signup_password, signup_org)
                        if result['success']:
                            st.success(result['message'])
                            st.rerun()
                        else:
                            st.error(result['message'])
            
            st.markdown("---")
            st.markdown("### Features")
            st.markdown("Multi-organization support")
            st.markdown("Real-time inventory tracking")
            st.markdown("Sales and purchase management")
            st.markdown("Supplier management")
            st.markdown("Advanced reporting")
            st.markdown("Data export")
            
        else:
            # User Info
            st.success(f"Welcome, {st.session_state.username}")
            st.caption(f"Organization: {st.session_state.organization}")
            st.caption(f"Role: {st.session_state.role}")
            
            if st.button("Logout", use_container_width=True, type="secondary"):
                logout_user()
            
            st.markdown("---")
            
            # Navigation
            pages = [
                ("Dashboard", "Dashboard"),
                ("Products", "Products"),
                ("Transactions", "Transactions"),
                ("Suppliers", "Suppliers"),
                ("Reports", "Reports"),
                ("Settings", "Settings")
            ]
            
            for page_name, page_id in pages:
                if st.button(
                    page_name,
                    key=f"nav_{page_id}",
                    use_container_width=True,
                    type="primary" if st.session_state.page == page_id else "secondary"
                ):
                    st.session_state.page = page_id
                    st.rerun()

def render_dashboard():
    """Render dashboard page"""
    st.markdown("<h1 class='main-header'>Dashboard</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.info("Please login to access your dashboard")
        return
    
    # Key Metrics
    metrics = get_key_metrics()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Total Products</div>
            <div class='metric-value'>{metrics.get('total_products', 0)}</div>
            <div class='metric-subtitle'>Active inventory</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Stock Value</div>
            <div class='metric-value'>{metrics.get('stock_value', '$0.00')}</div>
            <div class='metric-subtitle'>Current value</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        low_stock = metrics.get('low_stock', 0)
        badge_class = "badge-danger" if low_stock > 0 else "badge-success"
        badge_text = "Need attention" if low_stock > 0 else "All good"
        
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Low Stock</div>
            <div class='metric-value'>{low_stock}</div>
            <div class='metric-subtitle'>
                <span class='badge {badge_class}'>{badge_text}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Monthly Sales</div>
            <div class='metric-value'>{metrics.get('monthly_sales', '$0.00')}</div>
            <div class='metric-subtitle'>Last 30 days</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Quick Actions
    st.markdown("<h2 class='section-header'>Quick Actions</h2>", unsafe_allow_html=True)
    
    col_actions1, col_actions2, col_actions3, col_actions4 = st.columns(4)
    
    with col_actions1:
        if st.button("Add Product", use_container_width=True):
            st.session_state.page = "Products"
            st.rerun()
    
    with col_actions2:
        if st.button("Record Sale", use_container_width=True):
            st.session_state.page = "Transactions"
            st.rerun()
    
    with col_actions3:
        if st.button("Add Supplier", use_container_width=True):
            st.session_state.page = "Suppliers"
            st.rerun()
    
    with col_actions4:
        if st.button("View Reports", use_container_width=True):
            st.session_state.page = "Reports"
            st.rerun()
    
    # Recent Products
    st.markdown("<h2 class='section-header'>Recent Products</h2>", unsafe_allow_html=True)
    
    products = get_products(page_size=10)
    if not products.empty:
        # Format the dataframe for display
        display_df = products.copy()
        
        # Add status column
        def get_status(row):
            if row['quantity'] == 0:
                return '<span class="badge badge-danger">Out of Stock</span>'
            elif row['quantity'] <= row['reorder_level']:
                return '<span class="badge badge-warning">Low Stock</span>'
            else:
                return '<span class="badge badge-success">In Stock</span>'
        
        display_df['status'] = display_df.apply(get_status, axis=1)
        display_df['cost'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        display_df['price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        
        # Display as HTML table for better styling
        html_table = display_df[['sku', 'name', 'category', 'quantity', 'cost', 'price', 'status']].to_html(
            escape=False, index=False, classes='dataframe', border=0
        )
        st.markdown(html_table, unsafe_allow_html=True)
    else:
        st.info("No products found. Add your first product using the 'Add Product' button above.")
        
        # Sample data for new users
        with st.expander("Need sample data? Click here to add demo products"):
            if st.button("Add Sample Products"):
                sample_products = [
                    {
                        'sku': 'LAP-001', 'name': 'Laptop Pro', 'description': 'High-performance laptop',
                        'category': 'Electronics', 'supplier': 'Tech Supplies Inc', 'unit': 'pcs',
                        'cost_price': 800, 'sell_price': 1200, 'quantity': 15, 'min_quantity': 5,
                        'reorder_level': 10, 'location': 'Shelf A1', 'barcode': '123456789012',
                        'notes': 'Popular item, keep stocked'
                    },
                    {
                        'sku': 'DESK-001', 'name': 'Office Desk', 'description': 'Ergonomic office desk',
                        'category': 'Furniture', 'supplier': 'Office Furniture Co', 'unit': 'pcs',
                        'cost_price': 200, 'sell_price': 350, 'quantity': 8, 'min_quantity': 3,
                        'reorder_level': 5, 'location': 'Warehouse B', 'barcode': '234567890123',
                        'notes': 'Assembly required'
                    },
                    {
                        'sku': 'PEN-001', 'name': 'Premium Pen Set', 'description': 'Executive pen set',
                        'category': 'Stationery', 'supplier': 'Writing Supplies Ltd', 'unit': 'set',
                        'cost_price': 25, 'sell_price': 45, 'quantity': 50, 'min_quantity': 20,
                        'reorder_level': 30, 'location': 'Shelf C3', 'barcode': '345678901234',
                        'notes': 'Best seller'
                    }
                ]
                
                for product in sample_products:
                    product['organization'] = st.session_state.organization
                    add_product(product)
                
                st.success("Sample products added successfully!")
                st.rerun()

def render_products():
    """Render products management page"""
    st.markdown("<h1 class='main-header'>Products</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage products")
        return
    
    # Tabs for product management
    tab1, tab2, tab3 = st.tabs(["Product List", "Add Product", "Edit Product"])
    
    with tab1:
        # Search and filters
        col_search, col_filter, col_page = st.columns(3)
        
        with col_search:
            search_term = st.text_input("Search products", placeholder="SKU, name, description...")
        
        with col_filter:
            stock_filter = st.selectbox(
                "Stock Status",
                ["All", "In Stock", "Low Stock", "Out of Stock"]
            )
        
        with col_page:
            page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=1)
        
        page_number = st.number_input("Page", min_value=1, value=1, step=1)
        
        # Get products
        products = get_products(search=search_term, page=page_number, page_size=page_size)
        
        if not products.empty:
            # Apply stock filter
            if stock_filter == "Low Stock":
                products = products[products['quantity'] <= products['reorder_level']]
                products = products[products['quantity'] > 0]
            elif stock_filter == "Out of Stock":
                products = products[products['quantity'] == 0]
            elif stock_filter == "In Stock":
                products = products[products['quantity'] > 0]
            
            # Display product count
            st.caption(f"Showing {len(products)} products")
            
            # Display products in a nice dataframe
            display_df = products[['sku', 'name', 'category', 'quantity', 'cost_price', 'sell_price', 'location']].copy()
            display_df['cost_price'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['sell_price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            # Add stock status with colors
            def get_stock_status(row):
                if row['quantity'] == 0:
                    return "Out of Stock"
                elif row['quantity'] <= products[products['sku'] == row['sku']]['reorder_level'].values[0]:
                    return "Low Stock"
                else:
                    return "In Stock"
            
            display_df['status'] = display_df.apply(get_stock_status, axis=1)
            
            st.dataframe(
                display_df,
                use_container_width=True,
                column_config={
                    "sku": "SKU",
                    "name": "Product Name",
                    "category": "Category",
                    "quantity": "Quantity",
                    "cost_price": "Cost",
                    "sell_price": "Price",
                    "location": "Location",
                    "status": "Status"
                },
                hide_index=True
            )
            
            # Export option
            col_export, col_refresh = st.columns(2)
            with col_export:
                if st.button("Export to CSV", use_container_width=True):
                    csv = products.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="products_export.csv",
                        mime="text/csv",
                        key="export_csv"
                    )
            
            with col_refresh:
                if st.button("Refresh", use_container_width=True):
                    st.rerun()
                    
        else:
            st.info("No products found. Add your first product in the 'Add Product' tab.")
    
    with tab2:
        # Add product form
        with st.form("add_product_form", clear_on_submit=True):
            st.subheader("Add New Product")
            
            col1, col2 = st.columns(2)
            
            with col1:
                sku = st.text_input("SKU *", help="Unique product identifier")
                name = st.text_input("Product Name *")
                description = st.text_area("Description")
                category = st.text_input("Category")
                supplier = st.text_input("Supplier")
            
            with col2:
                unit = st.selectbox("Unit", ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"])
                location = st.text_input("Location", placeholder="Shelf A1, Warehouse B, etc.")
                barcode = st.text_input("Barcode (Optional)")
                notes = st.text_area("Notes")
            
            col3, col4, col5 = st.columns(3)
            
            with col3:
                cost_price = st.number_input(
                    "Cost Price *",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f",
                    help="Purchase cost per unit"
                )
                quantity = st.number_input(
                    "Initial Quantity *",
                    min_value=0,
                    value=0,
                    step=1,
                    help="Current stock level"
                )
            
            with col4:
                sell_price = st.number_input(
                    "Selling Price *",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f",
                    help="Selling price per unit"
                )
                min_quantity = st.number_input(
                    "Minimum Quantity",
                    min_value=0,
                    value=5,
                    step=1,
                    help="Minimum stock level before alert"
                )
            
            with col5:
                reorder_level = st.number_input(
                    "Reorder Level *",
                    min_value=0,
                    value=10,
                    step=1,
                    help="Reorder when stock reaches this level"
                )
            
            submitted = st.form_submit_button("Save Product", type="primary", use_container_width=True)
            
            if submitted:
                if not sku or not name:
                    st.error("SKU and Product Name are required fields")
                elif cost_price < 0 or sell_price < 0:
                    st.error("Prices cannot be negative")
                elif quantity < 0:
                    st.error("Quantity cannot be negative")
                else:
                    product_data = {
                        'sku': sku,
                        'name': name,
                        'description': description,
                        'category': category,
                        'supplier': supplier,
                        'unit': unit,
                        'cost_price': cost_price,
                        'sell_price': sell_price,
                        'quantity': quantity,
                        'min_quantity': min_quantity,
                        'reorder_level': reorder_level,
                        'location': location,
                        'barcode': barcode,
                        'notes': notes
                    }
                    
                    result = add_product(product_data)
                    if result['success']:
                        st.success(result['message'])
                        st.rerun()
                    else:
                        st.error(result['message'])
    
    with tab3:
        # Edit product form
        st.subheader("Edit Product")
        
        # Get all products for selection
        all_products = get_products(page_size=1000)
        
        if not all_products.empty:
            product_options = ["-- Select Product --"] + all_products['name'].tolist()
            selected_product = st.selectbox("Select product to edit", product_options)
            
            if selected_product != "-- Select Product --":
                # Get selected product data
                product_idx = all_products[all_products['name'] == selected_product].index[0]
                product_data = all_products.iloc[product_idx]
                
                with st.form("edit_product_form"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        edit_sku = st.text_input("SKU", value=product_data['sku'])
                        edit_name = st.text_input("Product Name", value=product_data['name'])
                        edit_description = st.text_area("Description", value=product_data['description'] or "")
                        edit_category = st.text_input("Category", value=product_data['category'] or "")
                        edit_supplier = st.text_input("Supplier", value=product_data['supplier'] or "")
                    
                    with col2:
                        edit_unit = st.selectbox("Unit", 
                                               ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"],
                                               index=["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"].index(
                                                   product_data['unit'] if product_data['unit'] in 
                                                   ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"] 
                                                   else "pcs"
                                               ))
                        edit_location = st.text_input("Location", value=product_data['location'] or "")
                        edit_barcode = st.text_input("Barcode", value=product_data['barcode'] or "")
                        edit_notes = st.text_area("Notes", value=product_data['notes'] or "")
                    
                    col3, col4, col5 = st.columns(3)
                    
                    with col3:
                        edit_cost = st.number_input(
                            "Cost Price",
                            min_value=0.0,
                            value=float(product_data['cost_price']),
                            step=0.01,
                            format="%.2f"
                        )
                        edit_quantity = st.number_input(
                            "Quantity",
                            min_value=0,
                            value=int(product_data['quantity']),
                            step=1
                        )
                    
                    with col4:
                        edit_price = st.number_input(
                            "Selling Price",
                            min_value=0.0,
                            value=float(product_data['sell_price']),
                            step=0.01,
                            format="%.2f"
                        )
                        edit_min_qty = st.number_input(
                            "Minimum Quantity",
                            min_value=0,
                            value=int(product_data['min_quantity']),
                            step=1
                        )
                    
                    with col5:
                        edit_reorder = st.number_input(
                            "Reorder Level",
                            min_value=0,
                            value=int(product_data['reorder_level']),
                            step=1
                        )
                    
                    col_update, col_delete = st.columns(2)
                    
                    with col_update:
                        update_submitted = st.form_submit_button("Update Product", use_container_width=True)
                    
                    with col_delete:
                        delete_clicked = st.form_submit_button("Delete Product", type="secondary", use_container_width=True)
                    
                    if update_submitted:
                        updated_data = {
                            'sku': edit_sku,
                            'name': edit_name,
                            'description': edit_description,
                            'category': edit_category,
                            'supplier': edit_supplier,
                            'unit': edit_unit,
                            'cost_price': edit_cost,
                            'sell_price': edit_price,
                            'quantity': edit_quantity,
                            'min_quantity': edit_min_qty,
                            'reorder_level': edit_reorder,
                            'location': edit_location,
                            'barcode': edit_barcode,
                            'notes': edit_notes
                        }
                        
                        result = update_product(product_data['product_id'], updated_data)
                        if result['success']:
                            st.success(result['message'])
                            st.rerun()
                        else:
                            st.error(result['message'])
                    
                    if delete_clicked:
                        # Confirm deletion
                        st.warning(f"Are you sure you want to delete '{product_data['name']}'?")
                        if st.button("Confirm Delete", type="primary"):
                            result = delete_product(product_data['product_id'])
                            if result['success']:
                                st.success(result['message'])
                                st.rerun()
                            else:
                                st.error(result['message'])
        else:
            st.info("No products available to edit. Add products first.")

def render_transactions():
    """Render transactions page"""
    st.markdown("<h1 class='main-header'>Transactions</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view transactions")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("Sales recording functionality coming soon")
        st.write("Future features:")
        st.write("Record sales transactions")
        st.write("Process purchase orders")
        st.write("Stock adjustments")
        st.write("Transaction history")
    
    with col2:
        st.info("Transaction Types")
        st.write("1. Sales - Customer purchases")
        st.write("2. Purchases - Restocking inventory")
        st.write("3. Adjustments - Stock corrections")
        st.write("4. Transfers - Location transfers")

def render_suppliers():
    """Render suppliers page"""
    st.markdown("<h1 class='main-header'>Suppliers</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage suppliers")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("Supplier management coming soon")
        st.write("Future features:")
        st.write("Add and edit supplier information")
        st.write("Contact management")
        st.write("Purchase history")
        st.write("Performance ratings")
    
    with col2:
        st.info("Supplier Benefits")
        st.write("Track supplier performance")
        st.write("Manage payment terms")
        st.write("Monitor delivery times")
        st.write("Maintain contact details")

def render_reports():
    """Render reports page"""
    st.markdown("<h1 class='main-header'>Reports</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view reports")
        return
    
    # Simple report cards
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class='metric-card'>
            <div class='metric-title'>Inventory Report</div>
            <div class='metric-subtitle'>Stock levels by category</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Simple inventory chart
        try:
            org = get_current_organization()
            inventory_data = fetch_dataframe(
                """
                SELECT category, SUM(quantity) as total_qty
                FROM products 
                WHERE organization = ? AND quantity > 0
                GROUP BY category
                ORDER BY total_qty DESC
                LIMIT 5
                """,
                (org,)
            )
            
            if not inventory_data.empty:
                chart = alt.Chart(inventory_data).mark_bar().encode(
                    x='category:N',
                    y='total_qty:Q',
                    color=alt.Color('category:N', legend=None)
                ).properties(height=200)
                st.altair_chart(chart, use_container_width=True)
        except:
            pass
    
    with col2:
        st.markdown("""
        <div class='metric-card'>
            <div class='metric-title'>Stock Status</div>
            <div class='metric-subtitle'>Current inventory health</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Stock status summary
        try:
            org = get_current_organization()
            status_data = fetch_dataframe(
                """
                SELECT 
                    SUM(CASE WHEN quantity = 0 THEN 1 ELSE 0 END) as out_of_stock,
                    SUM(CASE WHEN quantity > 0 AND quantity <= reorder_level THEN 1 ELSE 0 END) as low_stock,
                    SUM(CASE WHEN quantity > reorder_level THEN 1 ELSE 0 END) as in_stock
                FROM products 
                WHERE organization = ?
                """,
                (org,)
            )
            
            if not status_data.empty:
                st.write(f"In Stock: {int(status_data.iloc[0]['in_stock'])}")
                st.write(f"Low Stock: {int(status_data.iloc[0]['low_stock'])}")
                st.write(f"Out of Stock: {int(status_data.iloc[0]['out_of_stock'])}")
        except:
            pass
    
    st.markdown("---")
    st.info("Advanced reporting features coming soon")

def render_settings():
    """Render settings page"""
    st.markdown("<h1 class='main-header'>Settings</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to access settings")
        return
    
    # Organization Settings
    with st.expander("Organization Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            currency = st.selectbox(
                "Default Currency",
                ["USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"],
                index=["USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"].index(
                    st.session_state.currency if st.session_state.currency in 
                    ["USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"] 
                    else "USD"
                ),
                key="currency_select"
            )
            st.session_state.currency = currency
        
        with col2:
            timezone = st.selectbox(
                "Time Zone",
                ["UTC", "America/New_York", "America/Chicago", "America/Denver", 
                 "America/Los_Angeles", "Europe/London", "Europe/Paris", "Asia/Tokyo",
                 "Asia/Singapore", "Australia/Sydney"],
                index=["UTC", "America/New_York", "America/Chicago", "America/Denver", 
                      "America/Los_Angeles", "Europe/London", "Europe/Paris", "Asia/Tokyo",
                      "Asia/Singapore", "Australia/Sydney"].index(
                    st.session_state.timezone if st.session_state.timezone in 
                    ["UTC", "America/New_York", "America/Chicago", "America/Denver", 
                     "America/Los_Angeles", "Europe/London", "Europe/Paris", "Asia/Tokyo",
                     "Asia/Singapore", "Australia/Sydney"] 
                    else "UTC"
                ),
                key="timezone_select"
            )
            st.session_state.timezone = timezone
    
    # User Settings
    with st.expander("User Settings"):
        st.write("Change Password")
        
        current_pass = st.text_input("Current Password", type="password", key="current_pass")
        new_pass = st.text_input("New Password", type="password", key="new_pass")
        confirm_pass = st.text_input("Confirm New Password", type="password", key="confirm_pass")
        
        col_change, _ = st.columns(2)
        with col_change:
            if st.button("Update Password", use_container_width=True):
                if not current_pass:
                    st.error("Please enter current password")
                elif new_pass != confirm_pass:
                    st.error("New passwords do not match")
                elif len(new_pass) < 8:
                    st.error("Password must be at least 8 characters")
                else:
                    # Verify current password
                    result = authenticate_user(st.session_state.username, current_pass)
                    if result['success']:
                        # Update password
                        password_hash, salt = hash_password(new_pass)
                        execute_query(
                            "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?",
                            (password_hash, salt, st.session_state.user_id)
                        )
                        st.success("Password updated successfully")
                    else:
                        st.error("Current password is incorrect")
    
    # System Settings
    with st.expander("System Settings"):
        col_sys1, col_sys2 = st.columns(2)
        
        with col_sys1:
            prevent_negative = st.checkbox("Prevent Negative Stock", value=True)
            auto_backup = st.checkbox("Automatic Backups", value=False)
        
        with col_sys2:
            email_alerts = st.checkbox("Email Alerts", value=False)
            low_stock_notify = st.checkbox("Low Stock Notifications", value=True)
        
        if st.button("Save System Settings"):
            st.success("Settings saved successfully")
    
    # Data Management
    with st.expander("Data Management"):
        col_data1, col_data2 = st.columns(2)
        
        with col_data1:
            if st.button("Export All Data", use_container_width=True, type="secondary"):
                # Export products
                products = get_products(page_size=1000)
                if not products.empty:
                    csv_data = products.to_csv(index=False)
                    st.download_button(
                        label="Download Products CSV",
                        data=csv_data,
                        file_name="invypro_products_export.csv",
                        mime="text/csv",
                        key="export_all"
                    )
                else:
                    st.info("No data to export")
        
        with col_data2:
            if st.button("View Activity Logs", use_container_width=True, type="secondary"):
                try:
                    org = get_current_organization()
                    logs = fetch_dataframe(
                        """
                        SELECT action, details, created_at 
                        FROM activity_logs 
                        WHERE organization = ? 
                        ORDER BY created_at DESC 
                        LIMIT 50
                        """,
                        (org,)
                    )
                    
                    if not logs.empty:
                        st.dataframe(logs, use_container_width=True)
                    else:
                        st.info("No activity logs found")
                except:
                    st.info("No activity logs available")
    
    # Danger Zone
    with st.expander("Danger Zone", expanded=False):
        st.warning("These actions cannot be undone. Proceed with caution.")
        
        if st.button("Reset Organization Data", type="secondary", use_container_width=True):
            st.error("This will delete ALL products and transactions for your organization.")
            
            confirm = st.checkbox("I understand this action cannot be undone")
            if confirm and st.button("CONFIRM RESET", type="primary", use_container_width=True):
                try:
                    org = get_current_organization()
                    execute_query("DELETE FROM transactions WHERE organization = ?", (org,))
                    execute_query("DELETE FROM products WHERE organization = ?", (org,))
                    execute_query("DELETE FROM suppliers WHERE organization = ?", (org,))
                    
                    log_activity(
                        user_id=st.session_state.user_id,
                        action="data_reset",
                        details="Reset all organization data"
                    )
                    
                    st.success("Organization data has been reset")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error resetting data: {str(e)}")

# ============================================================================
# MAIN APPLICATION
# ============================================================================
def main():
    """Main application function"""
    
    # Initialize database on first run
    if 'db_initialized' not in st.session_state:
        try:
            if Database.test_connection():
                initialize_database()
                st.session_state.db_initialized = True
                st.session_state.db_type = "SQLite"
            else:
                st.warning("Could not initialize database. Running in limited mode.")
        except Exception as e:
            st.warning(f"Database setup: {str(e)}")
    
    # Render sidebar
    render_sidebar()
    
    # Render main content based on current page
    pages = {
        "Dashboard": render_dashboard,
        "Products": render_products,
        "Transactions": render_transactions,
        "Suppliers": render_suppliers,
        "Reports": render_reports,
        "Settings": render_settings
    }
    
    page_func = pages.get(st.session_state.page, render_dashboard)
    page_func()
    
    # Footer
    #st.markdown("---")
    #col_footer1, col_footer2, col_footer3 = st.columns(3)
    #with col_footer2:
        #st.caption(f"InvyPro v1.0 • Database: {st.session_state.get('db_type', 'SQLite')}")

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    # Create necessary directories
    import os
    os.makedirs("data", exist_ok=True)
    os.makedirs("backups", exist_ok=True)
    
    # Run the application
    main()
