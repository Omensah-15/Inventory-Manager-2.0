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
from typing import Optional, Tuple
import pandas as pd
import numpy as np
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
        'default_currency': 'GHS',
        'default_timezone': 'UTC'
    }

config = Config()

# ============================================================================
# STREAMLIT PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="InvyPro Inventory Manager",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS
# ============================================================================
st.markdown("""
<style>
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
    
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > select,
    .stTextArea > div > div > textarea {
        border-radius: 6px;
        border: 1px solid var(--border) !important;
    }
    
    .dataframe {
        border-radius: 8px;
        border: 1px solid var(--border) !important;
    }
    
    .dataframe th {
        background-color: #f8fafc !important;
        font-weight: 600 !important;
    }
    
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
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
# DATABASE MANAGEMENT
# ============================================================================
class Database:
    @staticmethod
    def get_connection():
        conn = sqlite3.connect(config.DB_FILE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    @staticmethod
    def test_connection():
        try:
            conn = Database.get_connection()
            conn.execute("SELECT 1")
            conn.close()
            return True
        except:
            return False

@contextmanager
def db_session():
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
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        if fetch:
            return cur.fetchall()
        return cur.rowcount

def fetch_dataframe(query: str, params: Tuple = ()) -> pd.DataFrame:
    with db_session() as conn:
        return pd.read_sql_query(query, conn, params=params)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================
def initialize_database():
    schema_queries = [
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
            CHECK (type IN ('sale', 'purchase', 'adjustment')),
            CHECK (status IN ('pending', 'completed', 'cancelled'))
        );
        """,
        
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
        
        "CREATE INDEX IF NOT EXISTS idx_products_org ON products(organization);",
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_org ON transactions(organization);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at);"
    ]
    
    try:
        with db_session() as conn:
            cur = conn.cursor()
            for query in schema_queries:
                cur.execute(query)
        
        create_default_admin()
        return True
    except Exception as e:
        st.error(f"Database initialization failed: {str(e)}")
        return False

def create_default_admin():
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
    except:
        pass

# ============================================================================
# SECURITY & AUTHENTICATION
# ============================================================================
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
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
    computed, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(computed, stored_hash)

def register_user(username: str, email: str, password: str, organization: str):
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
        
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Username already exists"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def authenticate_user(username: str, password: str):
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
        
        if user[6] != 1:
            return {"success": False, "message": "Account is inactive"}
        
        if verify_password(user[2], user[3], password):
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
        pass

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================
def initialize_session():
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
    st.session_state.authenticated = True
    st.session_state.user_id = user_data['id']
    st.session_state.username = user_data['username']
    st.session_state.organization = user_data['organization']
    st.session_state.role = user_data['role']
    st.rerun()

def logout_user():
    if st.session_state.authenticated:
        log_activity(
            user_id=st.session_state.user_id,
            action="user_logout",
            details="User logged out"
        )
    
    currency = st.session_state.get('currency', 'GHS')
    timezone = st.session_state.get('timezone', 'UTC')
    
    keys = list(st.session_state.keys())
    for key in keys:
        del st.session_state[key]
    
    st.session_state.currency = currency
    st.session_state.timezone = timezone
    st.session_state.authenticated = False
    st.session_state.page = "Dashboard"
    st.rerun()

# ============================================================================
# DATA MANAGEMENT
# ============================================================================
def get_current_organization():
    return st.session_state.organization if st.session_state.authenticated else None

def get_products(search: str = "", page: int = 1, page_size: int = 50):
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
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
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
    org = get_current_organization()
    if not org:
        return {}
    
    try:
        total_products = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ?",
            (org,)
        ).iloc[0]['count']
        
        stock_value = fetch_dataframe(
            "SELECT SUM(quantity * cost_price) as value FROM products WHERE organization = ?",
            (org,)
        ).iloc[0]['value'] or 0
        
        low_stock = fetch_dataframe(
            """
            SELECT COUNT(*) as count 
            FROM products 
            WHERE organization = ? AND quantity <= reorder_level AND quantity > 0
            """,
            (org,)
        ).iloc[0]['count']
        
        out_of_stock = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ? AND quantity = 0",
            (org,)
        ).iloc[0]['count']
        
        monthly_sales = fetch_dataframe(
            """
            SELECT COALESCE(SUM(total_amount), 0) as sales
            FROM transactions 
            WHERE organization = ? 
                AND type = 'sale' 
                AND date(created_at) >= date('now', '-30 days')
            """,
            (org,)
        ).iloc[0]['sales']
        
        return {
            'total_products': total_products,
            'stock_value': f"{st.session_state.currency} {stock_value:,.2f}",
            'low_stock': low_stock,
            'out_of_stock': out_of_stock,
            'monthly_sales': f"{st.session_state.currency} {monthly_sales:,.2f}"
        }
    except Exception:
        return {}

def get_recent_transactions(limit: int = 10):
    org = get_current_organization()
    if not org:
        return pd.DataFrame()
    
    query = """
        SELECT 
            t.transaction_id,
            t.type,
            t.quantity,
            t.unit_price,
            t.total_amount,
            t.reference,
            t.created_at,
            p.sku,
            p.name as product_name,
            u.username as created_by_name
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        LEFT JOIN users u ON t.created_by = u.user_id
        WHERE t.organization = ?
        ORDER BY t.created_at DESC
        LIMIT ?
    """
    
    return fetch_dataframe(query, (org, limit))

def record_transaction(transaction_data: dict):
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
        product_id = transaction_data['product_id']
        trans_type = transaction_data['type']
        quantity = transaction_data['quantity']
        
        # Determine delta
        if trans_type == 'sale':
            delta = -abs(quantity)
        elif trans_type == 'purchase':
            delta = abs(quantity)
        elif trans_type == 'adjustment':
            delta = quantity  # can be negative
        
        # Get current quantity
        current_qty_row = execute_query(
            "SELECT quantity FROM products WHERE product_id = ? AND organization = ?",
            (product_id, org),
            fetch=True
        )
        
        if not current_qty_row:
            return {"success": False, "message": "Product not found"}
        
        current_qty = current_qty_row[0][0]
        new_quantity = current_qty + delta
        
        if new_quantity < 0:
            return {"success": False, "message": "Insufficient stock - transaction would result in negative inventory"}
        
        # Insert transaction
        execute_query(
            """
            INSERT INTO transactions (
                organization, product_id, type, quantity,
                unit_price, total_amount, reference, notes, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                org,
                product_id,
                trans_type,
                quantity,
                transaction_data['unit_price'],
                transaction_data['total_amount'],
                transaction_data['reference'],
                transaction_data['notes'],
                st.session_state.user_id
            )
        )
        
        # Update product quantity
        execute_query(
            "UPDATE products SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE product_id = ?",
            (new_quantity, product_id)
        )
        
        product_name = execute_query(
            "SELECT name FROM products WHERE product_id = ?",
            (product_id,),
            fetch=True
        )[0][0]
        
        log_activity(
            user_id=st.session_state.user_id,
            action="transaction_recorded",
            details=f"Recorded {trans_type} transaction: {quantity} units of {product_name}"
        )
        
        return {"success": True, "message": "Transaction recorded successfully"}
        
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

# ============================================================================
# UI COMPONENTS
# ============================================================================
def render_sidebar():
    with st.sidebar:
        st.markdown("## InvyPro")
        st.markdown("Professional Inventory Management")
        st.markdown("---")
        
        if not st.session_state.authenticated:
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
            st.markdown("- Multi-organization support")
            st.markdown("- Real-time inventory tracking")
            st.markdown("- Sales and purchase management")
            st.markdown("- Supplier management")
            st.markdown("- Advanced reporting with visuals")
            st.markdown("- Data export")
            
        else:
            st.success(f"Welcome, {st.session_state.username}")
            st.caption(f"Organization: {st.session_state.organization}")
            st.caption(f"Role: {st.session_state.role}")
            
            if st.button("Logout", use_container_width=True, type="secondary"):
                logout_user()
            
            st.markdown("---")
            
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
    st.markdown("<h1 class='main-header'>Dashboard</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.info("Please login to access your dashboard")
        return
    
    metrics = get_key_metrics()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Total Products</div>
            <div class='metric-value'>{metrics.get('total_products', 0)}</div>
            <div class='metric-subtitle'>Active inventory items</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Stock Value</div>
            <div class='metric-value'>{metrics.get('stock_value', 'GHS 0.00')}</div>
            <div class='metric-subtitle'>Current valuation</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Low Stock Items</div>
            <div class='metric-value'>{metrics.get('low_stock', 0)}</div>
            <div class='metric-subtitle'>Requires attention</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Monthly Sales</div>
            <div class='metric-value'>{metrics.get('monthly_sales', 'GHS 0.00')}</div>
            <div class='metric-subtitle'>Last 30 days</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("<h2 class='section-header'>Recent Transactions</h2>", unsafe_allow_html=True)
    
    transactions = get_recent_transactions(limit=10)
    if not transactions.empty:
        display_df = transactions.copy()
        display_df['unit_price'] = display_df['unit_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        display_df['total_amount'] = display_df['total_amount'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        
        st.dataframe(
            display_df[['created_at', 'type', 'sku', 'product_name', 'quantity', 'unit_price', 'total_amount', 'reference']],
            use_container_width=True,
            hide_index=True
        )
        
        if st.button("View All Transactions", use_container_width=True):
            st.session_state.page = "Transactions"
            st.rerun()
    else:
        st.info("No recent transactions found.")
    
    st.markdown("---")
    
    st.markdown("<h2 class='section-header'>Recent Products</h2>", unsafe_allow_html=True)
    
    products = get_products(page_size=10)
    if not products.empty:
        display_df = products[['sku', 'name', 'category', 'quantity', 'cost_price', 'sell_price']].copy()
        display_df['cost_price'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        display_df['sell_price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        
        display_df['status'] = np.where(
            products['quantity'] == 0, "Out of Stock",
            np.where(products['quantity'] <= products['reorder_level'], "Low Stock", "In Stock")
        )
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No products found. Add your first product using the Products menu.")

def render_products():
    st.markdown("<h1 class='main-header'>Products</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage products")
        return
    
    tab1, tab2, tab3 = st.tabs(["Product List", "Add Product", "Edit Product"])
    
    with tab1:
        col_search, col_filter, col_actions = st.columns([3, 2, 3])
        
        with col_search:
            search_term = st.text_input("Search products", placeholder="SKU, name, description...")
        
        with col_filter:
            stock_filter = st.selectbox("Stock Status", ["All", "In Stock", "Low Stock", "Out of Stock"])
        
        with col_actions:
            page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=1)
        
        page_number = st.number_input("Page", min_value=1, value=1, step=1)
        
        products = get_products(search=search_term, page=page_number, page_size=page_size)
        
        if not products.empty:
            if stock_filter == "Low Stock":
                products = products[(products['quantity'] <= products['reorder_level']) & (products['quantity'] > 0)]
            elif stock_filter == "Out of Stock":
                products = products[products['quantity'] == 0]
            elif stock_filter == "In Stock":
                products = products[products['quantity'] > products['reorder_level']]
            
            display_df = products[['sku', 'name', 'category', 'quantity', 'cost_price', 'sell_price', 'location']].copy()
            display_df['cost_price'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['sell_price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            display_df['status'] = np.where(
                products['quantity'] == 0, "Out of Stock",
                np.where(products['quantity'] <= products['reorder_level'], "Low Stock", "In Stock")
            )
            
            st.dataframe(display_df, use_container_width=True, hide_index=True)
            
            csv = products.to_csv(index=False)
            st.download_button(
                "Export Products to CSV",
                data=csv,
                file_name="products_export.csv",
                mime="text/csv",
                use_container_width=True
            )
        else:
            st.info("No products found.")
    
    with tab2:
        with st.form("add_product_form", clear_on_submit=True):
            st.subheader("Add New Product")
            
            col1, col2 = st.columns(2)
            
            with col1:
                sku = st.text_input("SKU *", help="Unique identifier")
                name = st.text_input("Product Name *")
                description = st.text_area("Description")
                category = st.text_input("Category")
                supplier = st.text_input("Supplier")
            
            with col2:
                unit = st.selectbox("Unit", ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"])
                location = st.text_input("Location", placeholder="Shelf A1, Warehouse B, etc.")
                barcode = st.text_input("Barcode (Optional)")
                notes = st.text_area("Notes")
            
            col3, col4 = st.columns(2)
            
            with col3:
                cost_price = st.number_input("Cost Price *", min_value=0.0, step=0.01, format="%.2f")
                sell_price = st.number_input("Selling Price *", min_value=0.0, step=0.01, format="%.2f")
                quantity = st.number_input("Initial Quantity *", min_value=0, step=1)
            
            with col4:
                min_quantity = st.number_input("Minimum Quantity", min_value=0, value=5, step=1)
                reorder_level = st.number_input("Reorder Level *", min_value=0, value=10, step=1)
            
            submitted = st.form_submit_button("Save Product", type="primary", use_container_width=True)
            
            if submitted:
                if not sku or not name:
                    st.error("SKU and Product Name are required")
                else:
                    result = add_product({
                        'sku': sku, 'name': name, 'description': description,
                        'category': category, 'supplier': supplier, 'unit': unit,
                        'cost_price': cost_price, 'sell_price': sell_price,
                        'quantity': quantity, 'min_quantity': min_quantity,
                        'reorder_level': reorder_level, 'location': location,
                        'barcode': barcode, 'notes': notes
                    })
                    if result['success']:
                        st.success(result['message'])
                        st.rerun()
                    else:
                        st.error(result['message'])
    
    with tab3:
        st.subheader("Edit Product")
        
        all_products = get_products(page_size=10000)
        
        if not all_products.empty:
            product_options = ["-- Select Product --"] + [f"{row['sku']} - {row['name']}" for _, row in all_products.iterrows()]
            selected = st.selectbox("Select product to edit", product_options)
            
            if selected != "-- Select Product --":
                product_data = all_products[all_products['sku'] == selected.split(' - ')[0]].iloc[0]
                
                st.info(f"SKU: {product_data['sku']} (cannot be changed)")
                
                with st.form("edit_product_form"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        name = st.text_input("Product Name", value=product_data['name'])
                        description = st.text_area("Description", value=product_data['description'] or "")
                        category = st.text_input("Category", value=product_data['category'] or "")
                        supplier = st.text_input("Supplier", value=product_data['supplier'] or "")
                    
                    with col2:
                        unit = st.selectbox("Unit", ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"],
                                           index=["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"].index(product_data['unit']))
                        location = st.text_input("Location", value=product_data['location'] or "")
                        barcode = st.text_input("Barcode", value=product_data['barcode'] or "")
                        notes = st.text_area("Notes", value=product_data['notes'] or "")
                    
                    col3, col4 = st.columns(2)
                    
                    with col3:
                        cost_price = st.number_input("Cost Price", min_value=0.0, value=float(product_data['cost_price']), step=0.01)
                        quantity = st.number_input("Current Quantity", min_value=0, value=int(product_data['quantity']), step=1)
                    
                    with col4:
                        sell_price = st.number_input("Selling Price", min_value=0.0, value=float(product_data['sell_price']), step=0.01)
                        min_quantity = st.number_input("Minimum Quantity", min_value=0, value=int(product_data['min_quantity']), step=1)
                        reorder_level = st.number_input("Reorder Level", min_value=0, value=int(product_data['reorder_level']), step=1)
                    
                    col_update, col_delete = st.columns(2)
                    
                    if col_update.form_submit_button("Update Product", type="primary", use_container_width=True):
                        result = update_product(product_data['product_id'], {
                            'name': name, 'description': description, 'category': category,
                            'supplier': supplier, 'unit': unit, 'cost_price': cost_price,
                            'sell_price': sell_price, 'quantity': quantity,
                            'min_quantity': min_quantity, 'reorder_level': reorder_level,
                            'location': location, 'barcode': barcode, 'notes': notes
                        })
                        if result['success']:
                            st.success(result['message'])
                            st.rerun()
                        else:
                            st.error(result['message'])
                    
                    if col_delete.form_submit_button("Delete Product", type="secondary", use_container_width=True):
                        result = delete_product(product_data['product_id'])
                        if result['success']:
                            st.success(result['message'])
                            st.rerun()
                        else:
                            st.error(result['message'])
        else:
            st.info("No products available to edit.")

def render_transactions():
    st.markdown("<h1 class='main-header'>Transactions</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage transactions")
        return
    
    tab1, tab2 = st.tabs(["Record Transaction", "Transaction History"])
    
    with tab1:
        with st.form("record_transaction_form", clear_on_submit=True):
            st.subheader("Record New Transaction")
            
            col_type, col_ref = st.columns(2)
            with col_type:
                transaction_type = st.selectbox("Transaction Type *", ["sale", "purchase", "adjustment"])
            with col_ref:
                reference = st.text_input("Reference (Optional)")
            
            products = get_products(page_size=10000)
            
            if not products.empty:
                product_options = ["-- Select Product --"] + [f"{row['sku']} - {row['name']}" for _, row in products.iterrows()]
                selected_product = st.selectbox("Select Product *", product_options)
                
                if selected_product != "-- Select Product --":
                    sku_selected = selected_product.split(" - ")[0]
                    product_info = products[products['sku'] == sku_selected].iloc[0]
                    product_id = product_info['product_id']
                    
                    st.info(f"Current Stock: {product_info['quantity']} {product_info['unit']}")
                    
                    min_val = None if transaction_type == "adjustment" else 1
                    default_qty = 0 if transaction_type == "adjustment" else 1
                    
                    quantity = st.number_input(
                        "Quantity *",
                        min_value=min_val,
                        value=default_qty,
                        step=1
                    )
                    
                    if transaction_type == "adjustment":
                        st.info("For adjustments: enter positive to increase stock, negative to decrease stock")
                    
                    if transaction_type == "sale" and quantity > product_info['quantity']:
                        st.error(f"Insufficient stock. Only {product_info['quantity']} available.")
                    
                    if transaction_type == "adjustment":
                        unit_price = 0.0
                        total_amount = 0.0
                        st.info("Adjustments do not record monetary value.")
                    else:
                        default_price = product_info['sell_price'] if transaction_type == "sale" else product_info['cost_price']
                        unit_price = st.number_input("Unit Price *", min_value=0.0, value=float(default_price), step=0.01)
                        total_amount = quantity * unit_price
                        st.markdown(f"**Total Amount:** {st.session_state.currency} {total_amount:,.2f}")
                    
                    notes = st.text_area("Notes (Optional)")
                else:
                    product_id = None
                    quantity = 1
                    unit_price = 0.0
                    total_amount = 0.0
                    notes = ""
            else:
                st.info("No products found. Add products first.")
                product_id = None
                quantity = 1
                unit_price = 0.0
                total_amount = 0.0
                notes = ""
            
            submitted = st.form_submit_button("Record Transaction", type="primary", use_container_width=True)
            
            if submitted:
                if not products.empty and selected_product == "-- Select Product --":
                    st.error("Please select a product")
                elif product_id is None:
                    st.error("No products available")
                elif transaction_type == "sale" and quantity > product_info['quantity']:
                    st.error("Insufficient stock")
                else:
                    result = record_transaction({
                        'product_id': product_id,
                        'type': transaction_type,
                        'quantity': quantity,
                        'unit_price': unit_price,
                        'total_amount': total_amount,
                        'reference': reference,
                        'notes': notes
                    })
                    if result['success']:
                        st.success(result['message'])
                        st.rerun()
                    else:
                        st.error(result['message'])
    
    with tab2:
        st.subheader("Transaction History")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            filter_type = st.selectbox("Type", ["All", "sale", "purchase", "adjustment"])
        with col2:
            date_range = st.selectbox("Period", ["Last 7 days", "Last 30 days", "Last 90 days", "All time"])
        with col3:
            limit = st.number_input("Max records", min_value=10, max_value=500, value=100, step=10)
        
        org = get_current_organization()
        query = """
            SELECT t.transaction_id, t.type, t.quantity, t.unit_price, t.total_amount,
                   t.reference, t.created_at, p.sku, p.name as product_name
            FROM transactions t
            JOIN products p ON t.product_id = p.product_id
            WHERE t.organization = ?
        """
        params = [org]
        
        if filter_type != "All":
            query += " AND t.type = ?"
            params.append(filter_type)
        
        if date_range == "Last 7 days":
            query += " AND t.created_at >= datetime('now', '-7 days')"
        elif date_range == "Last 30 days":
            query += " AND t.created_at >= datetime('now', '-30 days')"
        elif date_range == "Last 90 days":
            query += " AND t.created_at >= datetime('now', '-90 days')"
        
        query += " ORDER BY t.created_at DESC LIMIT ?"
        params.append(limit)
        
        transactions = fetch_dataframe(query, tuple(params))
        
        if not transactions.empty:
            display_df = transactions.copy()
            display_df['unit_price'] = display_df['unit_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['total_amount'] = display_df['total_amount'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            st.dataframe(display_df[['created_at', 'type', 'sku', 'product_name', 'quantity', 'unit_price', 'total_amount', 'reference']],
                         use_container_width=True, hide_index=True)
            
            csv = transactions.to_csv(index=False)
            st.download_button("Export History to CSV", csv, "transaction_history.csv", "text/csv", use_container_width=True)
        else:
            st.info("No transactions found.")

def render_suppliers():
    st.markdown("<h1 class='main-header'>Suppliers</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage suppliers")
        return
    
    tab1, tab2, tab3 = st.tabs(["Supplier List", "Add Supplier", "Edit Supplier"])
    
    org = get_current_organization()
    
    with tab1:
        suppliers = fetch_dataframe("SELECT * FROM suppliers WHERE organization = ? ORDER BY name", (org,))
        
        if not suppliers.empty:
            st.dataframe(suppliers[['name', 'contact_person', 'email', 'phone', 'address']], use_container_width=True, hide_index=True)
            
            csv = suppliers.to_csv(index=False)
            st.download_button("Export Suppliers", csv, "suppliers.csv", "text/csv", use_container_width=True)
        else:
            st.info("No suppliers found.")
    
    with tab2:
        with st.form("add_supplier_form", clear_on_submit=True):
            st.subheader("Add New Supplier")
            
            name = st.text_input("Supplier Name *")
            contact_person = st.text_input("Contact Person")
            email = st.text_input("Email")
            phone = st.text_input("Phone")
            address = st.text_area("Address")
            payment_terms = st.text_input("Payment Terms")
            
            if st.form_submit_button("Save Supplier", type="primary", use_container_width=True):
                if not name:
                    st.error("Supplier name is required")
                else:
                    try:
                        execute_query(
                            """
                            INSERT INTO suppliers (organization, name, contact_person, email, phone, address, payment_terms)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (org, name, contact_person, email, phone, address, payment_terms)
                        )
                        st.success("Supplier added successfully")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Supplier name already exists")
    
    with tab3:
        st.subheader("Edit or Delete Supplier")
        
        suppliers = fetch_dataframe("SELECT * FROM suppliers WHERE organization = ? ORDER BY name", (org,))
        
        if not suppliers.empty:
            supplier_options = ["-- Select Supplier --"] + suppliers['name'].tolist()
            selected = st.selectbox("Select supplier", supplier_options)
            
            if selected != "-- Select Supplier --":
                supplier_data = suppliers[suppliers['name'] == selected].iloc[0]
                
                with st.form("edit_supplier_form"):
                    name = st.text_input("Supplier Name *", value=supplier_data['name'])
                    contact_person = st.text_input("Contact Person", value=supplier_data['contact_person'] or "")
                    email = st.text_input("Email", value=supplier_data['email'] or "")
                    phone = st.text_input("Phone", value=supplier_data['phone'] or "")
                    address = st.text_area("Address", value=supplier_data['address'] or "")
                    payment_terms = st.text_input("Payment Terms", value=supplier_data['payment_terms'] or "")
                    
                    col_update, col_delete = st.columns(2)
                    
                    if col_update.form_submit_button("Update Supplier", type="primary", use_container_width=True):
                        if not name:
                            st.error("Name required")
                        else:
                            try:
                                execute_query(
                                    """
                                    UPDATE suppliers SET name = ?, contact_person = ?, email = ?, phone = ?, address = ?, payment_terms = ?
                                    WHERE supplier_id = ? AND organization = ?
                                    """,
                                    (name, contact_person, email, phone, address, payment_terms, supplier_data['supplier_id'], org)
                                )
                                st.success("Supplier updated")
                                st.rerun()
                            except sqlite3.IntegrityError:
                                st.error("Supplier name already exists")
                    
                    if col_delete.form_submit_button("Delete Supplier", type="secondary", use_container_width=True):
                        execute_query("DELETE FROM suppliers WHERE supplier_id = ? AND organization = ?", (supplier_data['supplier_id'], org))
                        st.success("Supplier deleted")
                        st.rerun()

def render_reports():
    st.markdown("<h1 class='main-header'>Reports</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view reports")
        return
    
    org = get_current_organization()
    
    tab1, tab2, tab3, tab4 = st.tabs(["Inventory Overview", "Sales & Purchases", "Stock Alerts", "Financial Summary"])
    
    with tab1:
        st.subheader("Inventory Overview")
        
        metrics = get_key_metrics()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Products", metrics.get('total_products', 0))
        c2.metric("Stock Value", metrics.get('stock_value', 'GHS 0.00'))
        c3.metric("Low Stock", metrics.get('low_stock', 0))
        c4.metric("Out of Stock", metrics.get('out_of_stock', 0))
        
        category_data = fetch_dataframe("""
            SELECT category, 
                   SUM(quantity) as total_quantity,
                   SUM(quantity * cost_price) as total_value
            FROM products 
            WHERE organization = ? AND quantity > 0
            GROUP BY category
        """, (org,))
        
        if not category_data.empty:
            col_ch1, col_ch2 = st.columns(2)
            with col_ch1:
                chart_qty = alt.Chart(category_data).mark_bar(color='#2563eb').encode(
                    x=alt.X('category:N', sort='-y'),
                    y='total_quantity:Q',
                    tooltip=['category', 'total_quantity']
                ).properties(title="Quantity by Category", height=350)
                st.altair_chart(chart_qty, use_container_width=True)
            
            with col_ch2:
                chart_value = alt.Chart(category_data).mark_arc().encode(
                    theta='total_value:Q',
                    color='category:N',
                    tooltip=['category', 'total_value']
                ).properties(title="Value by Category", height=350)
                st.altair_chart(chart_value, use_container_width=True)
        
        top_valuable = fetch_dataframe("""
            SELECT sku, name, quantity, cost_price, (quantity * cost_price) as value
            FROM products WHERE organization = ? ORDER BY value DESC LIMIT 10
        """, (org,))
        
        if not top_valuable.empty:
            top_valuable['value'] = top_valuable['value'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            st.subheader("Top 10 Most Valuable Products")
            st.dataframe(top_valuable[['sku', 'name', 'quantity', 'cost_price', 'value']], use_container_width=True)
        
        full_inventory = get_products(page_size=100000)
        st.download_button(
            "Download Full Inventory Report (CSV)",
            full_inventory.to_csv(index=False),
            "full_inventory_report.csv",
            "text/csv",
            use_container_width=True
        )
    
    with tab2:
        st.subheader("Sales & Purchases Report")
        
        col_date1, col_date2 = st.columns(2)
        with col_date1:
            start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=30))
        with col_date2:
            end_date = st.date_input("End Date", value=datetime.now())
        
        if st.button("Generate Report", type="primary"):
            sales_daily = fetch_dataframe("""
                SELECT DATE(created_at) as date, SUM(total_amount) as amount
                FROM transactions WHERE organization = ? AND type = 'sale'
                AND DATE(created_at) BETWEEN ? AND ?
                GROUP BY date ORDER BY date
            """, (org, str(start_date), str(end_date)))
            
            purchases_daily = fetch_dataframe("""
                SELECT DATE(created_at) as date, SUM(total_amount) as amount
                FROM transactions WHERE organization = ? AND type = 'purchase'
                AND DATE(created_at) BETWEEN ? AND ?
                GROUP BY date ORDER BY date
            """, (org, str(start_date), str(end_date)))
            
            if not sales_daily.empty:
                total_sales = sales_daily['amount'].sum()
                st.metric("Total Sales", f"{st.session_state.currency} {total_sales:,.2f}")
                chart_sales = alt.Chart(sales_daily).mark_line(color='green').encode(
                    x='date:T', y='amount:Q'
                ).properties(title="Daily Sales Trend")
                st.altair_chart(chart_sales, use_container_width=True)
                st.download_button("Download Sales Data", sales_daily.to_csv(index=False), f"sales_{start_date}_to_{end_date}.csv")
            
            if not purchases_daily.empty:
                total_purchases = purchases_daily['amount'].sum()
                st.metric("Total Purchases", f"{st.session_state.currency} {total_purchases:,.2f}")
                chart_purchases = alt.Chart(purchases_daily).mark_line(color='orange').encode(
                    x='date:T', y='amount:Q'
                ).properties(title="Daily Purchases Trend")
                st.altair_chart(chart_purchases, use_container_width=True)
                st.download_button("Download Purchases Data", purchases_daily.to_csv(index=False), f"purchases_{start_date}_to_{end_date}.csv")
    
    with tab3:
        st.subheader("Stock Alerts")
        
        low_stock = fetch_dataframe("""
            SELECT sku, name, quantity, reorder_level, (reorder_level - quantity) as needed
            FROM products WHERE organization = ? AND quantity <= reorder_level AND quantity > 0
            ORDER BY quantity ASC
        """, (org,))
        
        out_stock = fetch_dataframe("""
            SELECT sku, name, quantity FROM products WHERE organization = ? AND quantity = 0
        """, (org,))
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Low Stock Items", len(low_stock))
            if not low_stock.empty:
                st.dataframe(low_stock, use_container_width=True)
        
        with col2:
            st.metric("Out of Stock Items", len(out_stock))
            if not out_stock.empty:
                st.dataframe(out_stock, use_container_width=True)
    
    with tab4:
        st.subheader("Financial Summary")
        
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            start_f = st.date_input("Period Start", value=datetime.now() - timedelta(days=30))
        with col_f2:
            end_f = st.date_input("Period End", value=datetime.now())
        
        if st.button("Calculate Summary"):
            revenue_row = fetch_dataframe("""
                SELECT COALESCE(SUM(total_amount), 0) as revenue
                FROM transactions WHERE organization = ? AND type = 'sale'
                AND DATE(created_at) BETWEEN ? AND ?
            """, (org, str(start_f), str(end_f)))
            revenue = revenue_row.iloc[0]['revenue']
            
            cogs_row = fetch_dataframe("""
                SELECT COALESCE(SUM(t.quantity * p.cost_price), 0) as cogs
                FROM transactions t JOIN products p ON t.product_id = p.product_id
                WHERE t.organization = ? AND t.type = 'sale'
                AND DATE(created_at) BETWEEN ? AND ?
            """, (org, str(start_f), str(end_f)))
            cogs = cogs_row.iloc[0]['cogs']
            
            gross_profit = revenue - cogs
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Revenue", f"{st.session_state.currency} {revenue:,.2f}")
            c2.metric("COGS (approx)", f"{st.session_state.currency} {cogs:,.2f}")
            c3.metric("Gross Profit (approx)", f"{st.session_state.currency} {gross_profit:,.2f}")

def render_settings():
    st.markdown("<h1 class='main-header'>Settings</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to access settings")
        return
    
    with st.expander("Organization Settings", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            currency = st.selectbox(
                "Currency",
                ["GHS", "USD", "EUR", "GBP", "CAD"],
                index=["GHS", "USD", "EUR", "GBP", "CAD"].index(st.session_state.currency)
            )
            if currency != st.session_state.currency:
                st.session_state.currency = currency
                st.success("Currency updated")
        
        with col2:
            timezone = st.selectbox(
                "Time Zone",
                ["UTC", "Africa/Accra", "America/New_York", "Europe/London"],
                index=["UTC", "Africa/Accra", "America/New_York", "Europe/London"].index(st.session_state.timezone)
            )
            if timezone != st.session_state.timezone:
                st.session_state.timezone = timezone
                st.success("Time zone updated")

def main():
    if 'db_initialized' not in st.session_state:
        if Database.test_connection() or initialize_database():
            st.session_state.db_initialized = True
    
    render_sidebar()
    
    pages = {
        "Dashboard": render_dashboard,
        "Products": render_products,
        "Transactions": render_transactions,
        "Suppliers": render_suppliers,
        "Reports": render_reports,
        "Settings": render_settings
    }
    
    pages.get(st.session_state.page, render_dashboard)()
    
    st.markdown("---")
    st.caption("InvyPro v1.0 - Professional Inventory Management System")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    main()
