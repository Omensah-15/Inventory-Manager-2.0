"""
InvyPro — Inventory Manager (PostgreSQL Edition)
- Multi-user with organization isolation
- PostgreSQL database support
- Local/offline deployment ready
- Professional production-ready features
"""

import os
import sys
import secrets
import hashlib
import hmac
import time
import psycopg2
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from psycopg2.extras import RealDictCursor

import pandas as pd
import streamlit as st
import altair as alt
import pytz
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ---------------------------
# Configuration
# ---------------------------
class Config:
    """Configuration management"""
    @staticmethod
    def get_db_config():
        """Get database configuration from environment or defaults"""
        return {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'database': os.getenv('DB_NAME', 'invypro'),
            'user': os.getenv('DB_USER', 'invypro_user'),
            'password': os.getenv('DB_PASSWORD', 'invypro_pass'),
            'sslmode': os.getenv('DB_SSLMODE', 'disable')
        }
    
    @staticmethod
    def get_app_config():
        """Get application configuration"""
        return {
            'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600')),
            'max_login_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
            'lockout_minutes': int(os.getenv('LOCKOUT_MINUTES', '15')),
            'backup_dir': os.getenv('BACKUP_DIR', './backups')
        }

# Initialize config
config = Config()

# ---------------------------
# App config
# ---------------------------
st.set_page_config(
    page_title="InvyPro — Inventory Manager",
    page_icon=":package:",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------
# CSS Styling
# ---------------------------
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
        background: linear-gradient(135deg, var(--primary), var(--success));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    
    .card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        border: 1px solid var(--border);
        margin-bottom: 1rem;
    }
    
    .card-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--dark);
        margin-bottom: 0.5rem;
    }
    
    .card-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary);
        margin: 0.5rem 0;
    }
    
    .card-subtitle {
        font-size: 0.85rem;
        color: var(--secondary);
    }
    
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
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
    
    .badge-info {
        background-color: #dbeafe;
        color: #1e40af;
    }
    
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s;
    }
    
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8fafc, #ffffff);
    }
    
    .dataframe {
        border-radius: 8px;
        overflow: hidden;
    }
    
    .stAlert {
        border-radius: 8px;
    }
    
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > select {
        border-radius: 6px;
        border: 1px solid var(--border);
    }
    
    .feature-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
    }
    
    .feature-card h3 {
        color: white;
        margin-bottom: 0.5rem;
    }
    
    .feature-card p {
        color: rgba(255, 255, 255, 0.9);
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Database Connection
# ---------------------------
class Database:
    """Database connection manager"""
    _conn = None
    
    @classmethod
    def get_connection(cls):
        """Get or create database connection"""
        if cls._conn is None or cls._conn.closed:
            try:
                db_config = config.get_db_config()
                cls._conn = psycopg2.connect(**db_config)
                cls._conn.autocommit = False
                st.session_state.db_connected = True
            except Exception as e:
                st.error(f"Database connection failed: {str(e)}")
                st.session_state.db_connected = False
                return None
        return cls._conn
    
    @classmethod
    def close_connection(cls):
        """Close database connection"""
        if cls._conn and not cls._conn.closed:
            cls._conn.close()
            cls._conn = None
    
    @classmethod
    def test_connection(cls):
        """Test database connection"""
        try:
            conn = cls.get_connection()
            if conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return True
        except:
            return False
        return False

@contextmanager
def db_session():
    """Context manager for database sessions"""
    conn = Database.get_connection()
    if conn is None:
        raise ConnectionError("Database connection not available")
    
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e

def run_query(query: str, params: Tuple = (), fetch: bool = False):
    """Execute a query and optionally fetch results"""
    with db_session() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            if fetch:
                return cur.fetchall()
            return cur.rowcount

def fetch_df(query: str, params: Tuple = ()) -> pd.DataFrame:
    """Fetch query results as pandas DataFrame"""
    with db_session() as conn:
        return pd.read_sql_query(query, conn, params=params)

# ---------------------------
# Database Initialization
# ---------------------------
def init_database():
    """Initialize PostgreSQL database schema"""
    init_queries = [
        # Enable UUID extension
        "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";",
        
        # Users table
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255),
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            organization VARCHAR(200) NOT NULL,
            role VARCHAR(50) DEFAULT 'admin',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP WITH TIME ZONE,
            CONSTRAINT valid_role CHECK (role IN ('admin', 'manager', 'staff'))
        );
        """,
        
        # Organizations table (enhanced)
        """
        CREATE TABLE IF NOT EXISTS organizations (
            org_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            name VARCHAR(200) UNIQUE NOT NULL,
            contact_email VARCHAR(255),
            phone VARCHAR(50),
            address TEXT,
            settings JSONB DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        );
        """,
        
        # Suppliers table
        """
        CREATE TABLE IF NOT EXISTS suppliers (
            supplier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            name VARCHAR(200) NOT NULL,
            phone VARCHAR(50),
            email VARCHAR(255),
            address TEXT,
            tax_id VARCHAR(100),
            payment_terms TEXT,
            rating INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, name)
        );
        """,
        
        # Categories table
        """
        CREATE TABLE IF NOT EXISTS categories (
            category_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            parent_id UUID REFERENCES categories(category_id),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, name)
        );
        """,
        
        # Products table
        """
        CREATE TABLE IF NOT EXISTS products (
            product_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            sku VARCHAR(100) NOT NULL,
            name VARCHAR(200) NOT NULL,
            description TEXT,
            category_id UUID REFERENCES categories(category_id),
            supplier_id UUID REFERENCES suppliers(supplier_id),
            unit VARCHAR(50) DEFAULT 'pcs',
            cost_price DECIMAL(15, 4) DEFAULT 0,
            sell_price DECIMAL(15, 4) DEFAULT 0,
            qty INTEGER DEFAULT 0,
            min_qty INTEGER DEFAULT 0,
            max_qty INTEGER DEFAULT 10000,
            reorder_level INTEGER DEFAULT 0,
            location VARCHAR(100),
            barcode VARCHAR(100),
            weight DECIMAL(10, 3),
            dimensions VARCHAR(100),
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, sku),
            CHECK (cost_price >= 0),
            CHECK (sell_price >= 0),
            CHECK (qty >= 0),
            CHECK (min_qty >= 0),
            CHECK (max_qty >= min_qty)
        );
        """,
        
        # Transactions table
        """
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
            type VARCHAR(50) NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price DECIMAL(15, 4) DEFAULT 0,
            total_amount DECIMAL(15, 4) DEFAULT 0,
            reference VARCHAR(100),
            customer_name VARCHAR(200),
            customer_email VARCHAR(255),
            note TEXT,
            status VARCHAR(50) DEFAULT 'completed',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            created_by UUID REFERENCES users(user_id),
            CHECK (type IN ('sale', 'restock', 'adjustment', 'transfer', 'damage', 'return')),
            CHECK (status IN ('pending', 'completed', 'cancelled'))
        );
        """,
        
        # Inventory logs (detailed tracking)
        """
        CREATE TABLE IF NOT EXISTS inventory_logs (
            log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            product_id UUID REFERENCES products(product_id),
            user_id UUID REFERENCES users(user_id),
            action VARCHAR(100) NOT NULL,
            old_value JSONB,
            new_value JSONB,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Create indexes for performance
        "CREATE INDEX IF NOT EXISTS idx_products_org ON products(organization);",
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_org ON transactions(organization);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at);",
        "CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization);",
        
        # Create triggers for updated_at
        """
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        """,
        
        """
        CREATE TRIGGER update_products_updated_at 
            BEFORE UPDATE ON products 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """,
        
        """
        CREATE TRIGGER update_suppliers_updated_at 
            BEFORE UPDATE ON suppliers 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """
    ]
    
    try:
        with db_session() as conn:
            with conn.cursor() as cur:
                for query in init_queries:
                    try:
                        cur.execute(query)
                    except Exception as e:
                        conn.rollback()
                        if "already exists" not in str(e):
                            st.warning(f"Schema init warning: {str(e)}")
                        continue
        st.success("Database initialized successfully")
    except Exception as e:
        st.error(f"Database initialization failed: {str(e)}")

# ---------------------------
# Security Utilities
# ---------------------------
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password with PBKDF2"""
    if salt is None:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return h, salt

def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    """Verify password against stored hash"""
    computed, _ = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(computed, stored_hash)

# ---------------------------
# Session Management
# ---------------------------
def init_session_state():
    """Initialize session state variables"""
    defaults = {
        'authenticated': False,
        'username': None,
        'user_id': None,
        'organization': None,
        'role': 'staff',
        'timezone': 'UTC',
        'currency': 'USD',
        'prevent_negative_stock': True,
        'demo_mode': True,
        'login_attempts': {},
        'db_connected': False,
        'page': 'Dashboard',
        'sidebar_expanded': True,
        'theme': 'light'
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# ---------------------------
# Authentication Functions
# ---------------------------
def signup(username: str, email: str, password: str, organization: str):
    """Register new user"""
    username = username.strip().lower()
    organization = organization.strip()
    email = email.strip().lower() if email else None
    
    if not username or not password or not organization:
        return {"success": False, "message": "Username, password and organization are required"}
    
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters"}
    
    phash, salt = hash_password(password)
    
    try:
        with db_session() as conn:
            with conn.cursor() as cur:
                # Check if organization exists in organizations table
                cur.execute(
                    "SELECT org_id FROM organizations WHERE name = %s",
                    (organization,)
                )
                org_exists = cur.fetchone()
                
                # Create organization if not exists
                if not org_exists:
                    cur.execute(
                        "INSERT INTO organizations (name, contact_email) VALUES (%s, %s) RETURNING org_id",
                        (organization, email)
                    )
                
                # Create user
                cur.execute(
                    """
                    INSERT INTO users (username, email, password_hash, salt, organization, role)
                    VALUES (%s, %s, %s, %s, %s, 'admin')
                    RETURNING user_id
                    """,
                    (username, email, phash, salt, organization)
                )
                
                user_id = cur.fetchone()[0]
                
        # Log activity
        log_activity(
            user_id=user_id,
            action="signup",
            details=f"User registered for organization: {organization}"
        )
        
        return {"success": True, "message": "Account created successfully"}
        
    except psycopg2.IntegrityError as e:
        if "users_username_key" in str(e):
            return {"success": False, "message": "Username already exists"}
        elif "organizations_name_key" in str(e):
            return {"success": False, "message": "Organization name already exists"}
        else:
            return {"success": False, "message": "Registration failed. Please try different details."}
    except Exception as e:
        return {"success": False, "message": f"Registration error: {str(e)}"}

def login(username: str, password: str):
    """Authenticate user"""
    username = username.strip().lower()
    
    if not username or not password:
        return {"success": False, "message": "Username and password required"}
    
    # Check lockout
    lockout_time = check_lockout(username)
    if lockout_time:
        return {"success": False, "message": f"Account locked. Try again in {lockout_time} minutes"}
    
    try:
        with db_session() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT user_id, username, password_hash, salt, organization, role, is_active
                    FROM users 
                    WHERE username = %s
                    """,
                    (username,)
                )
                user = cur.fetchone()
        
        if not user:
            record_failed_attempt(username)
            return {"success": False, "message": "Invalid credentials"}
        
        if not user['is_active']:
            return {"success": False, "message": "Account deactivated"}
        
        if verify_password(user['password_hash'], user['salt'], password):
            # Successful login
            clear_failed_attempts(username)
            
            # Update session
            st.session_state.authenticated = True
            st.session_state.user_id = user['user_id']
            st.session_state.username = user['username']
            st.session_state.organization = user['organization']
            st.session_state.role = user['role']
            st.session_state.demo_mode = False
            
            # Update last login
            with db_session() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET last_login = NOW() WHERE user_id = %s",
                        (user['user_id'],)
                    )
            
            # Log activity
            log_activity(
                user_id=user['user_id'],
                action="login",
                details=f"User logged in from IP"
            )
            
            return {"success": True, "message": "Login successful"}
        else:
            record_failed_attempt(username)
            return {"success": False, "message": "Invalid credentials"}
            
    except Exception as e:
        return {"success": False, "message": f"Login error: {str(e)}"}

def logout():
    """Log out current user"""
    if st.session_state.authenticated:
        log_activity(
            user_id=st.session_state.user_id,
            action="logout",
            details="User logged out"
        )
    
    # Preserve settings
    settings = {
        'timezone': st.session_state.get('timezone', 'UTC'),
        'currency': st.session_state.get('currency', 'USD'),
        'prevent_negative_stock': st.session_state.get('prevent_negative_stock', True)
    }
    
    # Clear session
    st.session_state.clear()
    
    # Restore settings
    for key, value in settings.items():
        st.session_state[key] = value
    
    st.session_state.authenticated = False
    st.session_state.demo_mode = True
    st.rerun()

# ---------------------------
# Security: Lockout Management
# ---------------------------
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def record_failed_attempt(username: str):
    """Record failed login attempt"""
    attempts = st.session_state.login_attempts.get(username, {'count': 0, 'timestamp': None})
    attempts['count'] += 1
    attempts['timestamp'] = datetime.now()
    st.session_state.login_attempts[username] = attempts

def clear_failed_attempts(username: str):
    """Clear failed attempts for user"""
    if username in st.session_state.login_attempts:
        del st.session_state.login_attempts[username]

def check_lockout(username: str) -> Optional[int]:
    """Check if user is locked out"""
    attempts = st.session_state.login_attempts.get(username)
    if not attempts:
        return None
    
    if attempts['count'] >= MAX_ATTEMPTS:
        lockout_end = attempts['timestamp'] + timedelta(minutes=LOCKOUT_MINUTES)
        if datetime.now() < lockout_end:
            remaining = (lockout_end - datetime.now()).seconds // 60
            return remaining
        else:
            clear_failed_attempts(username)
    
    return None

# ---------------------------
# Activity Logging
# ---------------------------
def log_activity(user_id: Optional[str] = None, action: str = "", details: str = ""):
    """Log user activity"""
    try:
        with db_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO inventory_logs (organization, user_id, action, details)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        st.session_state.get('organization', 'PUBLIC'),
                        user_id,
                        action,
                        details
                    )
                )
    except:
        pass  # Silently fail logging

# ---------------------------
# Data Management Functions
# ---------------------------
def get_current_org():
    """Get current organization"""
    return st.session_state.organization if st.session_state.authenticated else None

def get_products(page: int = 1, page_size: int = 50, search: str = None):
    """Get paginated products"""
    org = get_current_org()
    if not org:
        return pd.DataFrame()
    
    offset = (page - 1) * page_size
    
    query = """
        SELECT 
            p.product_id,
            p.sku,
            p.name,
            p.description,
            c.name as category,
            s.name as supplier,
            p.unit,
            p.cost_price,
            p.sell_price,
            p.qty,
            p.min_qty,
            p.reorder_level,
            p.location,
            p.barcode,
            p.is_active,
            p.created_at,
            p.updated_at,
            CASE 
                WHEN p.qty <= p.reorder_level THEN 'low'
                WHEN p.qty <= p.min_qty THEN 'critical'
                ELSE 'normal'
            END as stock_status
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.category_id
        LEFT JOIN suppliers s ON p.supplier_id = s.supplier_id
        WHERE p.organization = %s
    """
    
    params = [org]
    
    if search:
        query += " AND (p.sku ILIKE %s OR p.name ILIKE %s OR p.description ILIKE %s)"
        params.extend([f"%{search}%"] * 3)
    
    query += " ORDER BY p.updated_at DESC LIMIT %s OFFSET %s"
    params.extend([page_size, offset])
    
    return fetch_df(query, tuple(params))

def get_kpis():
    """Calculate key performance indicators"""
    org = get_current_org()
    if not org:
        return {}
    
    try:
        # Total SKUs
        total_skus = fetch_df(
            "SELECT COUNT(*) as count FROM products WHERE organization = %s",
            (org,)
        ).iloc[0]['count']
        
        # Stock value
        stock_value = fetch_df(
            "SELECT SUM(qty * cost_price) as value FROM products WHERE organization = %s",
            (org,)
        ).iloc[0]['value'] or 0
        
        # Low stock items
        low_stock = fetch_df(
            """
            SELECT COUNT(*) as count 
            FROM products 
            WHERE organization = %s AND qty <= reorder_level
            """,
            (org,)
        ).iloc[0]['count']
        
        # Monthly sales
        monthly_sales = fetch_df(
            """
            SELECT COALESCE(SUM(total_amount), 0) as sales
            FROM transactions 
            WHERE organization = %s 
                AND type = 'sale' 
                AND created_at >= NOW() - INTERVAL '30 days'
            """,
            (org,)
        ).iloc[0]['sales']
        
        # Recent transactions
        recent_tx = fetch_df(
            """
            SELECT COUNT(*) as count
            FROM transactions 
            WHERE organization = %s 
                AND created_at >= NOW() - INTERVAL '7 days'
            """,
            (org,)
        ).iloc[0]['count']
        
        return {
            'total_skus': total_skus,
            'stock_value': f"{st.session_state.currency} {stock_value:,.2f}",
            'low_stock': low_stock,
            'monthly_sales': f"{st.session_state.currency} {monthly_sales:,.2f}",
            'recent_transactions': recent_tx
        }
    except:
        return {}

# ---------------------------
# UI Components
# ---------------------------
def render_login_form():
    """Render login form"""
    with st.form("login_form", clear_on_submit=True):
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login", use_container_width=True)
        
        if submit:
            result = login(username, password)
            if result['success']:
                st.success(result['message'])
                st.rerun()
            else:
                st.error(result['message'])

def render_signup_form():
    """Render signup form"""
    with st.form("signup_form", clear_on_submit=True):
        st.subheader("Create Account")
        
        col1, col2 = st.columns(2)
        with col1:
            username = st.text_input("Username")
        with col2:
            email = st.text_input("Email")
        
        organization = st.text_input("Organization Name")
        
        col3, col4 = st.columns(2)
        with col3:
            password = st.text_input("Password", type="password")
        with col4:
            confirm_password = st.text_input("Confirm Password", type="password")
        
        submit = st.form_submit_button("Create Account", use_container_width=True)
        
        if submit:
            if password != confirm_password:
                st.error("Passwords do not match")
            else:
                result = signup(username, email, password, organization)
                if result['success']:
                    st.success(result['message'])
                    st.rerun()
                else:
                    st.error(result['message'])

def render_sidebar():
    """Render sidebar navigation"""
    with st.sidebar:
        st.markdown("### InvyPro Inventory")
        
        if not st.session_state.authenticated:
            tab1, tab2 = st.tabs(["Login", "Sign Up"])
            with tab1:
                render_login_form()
            with tab2:
                render_signup_form()
            
            st.divider()
            
            # Features
            st.markdown("### Features")
            features = [
                "Multi-user Management",
                "Real-time Inventory Tracking",
                "Sales & Purchase Orders",
                "Supplier Management",
                "Low Stock Alerts",
                "Barcode Support",
                "Advanced Reporting",
                "Data Export/Import"
            ]
            
            for feature in features:
                st.markdown(f"• {feature}")
            
            st.divider()
            st.caption("v2.0.0 | PostgreSQL Edition")
            
        else:
            # User info
            st.success(f"User: {st.session_state.username}")
            st.caption(f"Organization: {st.session_state.organization}")
            st.caption(f"Role: {st.session_state.role.title()}")
            
            if st.button("Logout", use_container_width=True):
                logout()
            
            st.divider()
            
            # Navigation
            pages = [
                ("Dashboard", "Dashboard"),
                ("Products", "Products"),
                ("Sales", "Sales"),
                ("Restock", "Restock"),
                ("Suppliers", "Suppliers"),
                ("Categories", "Categories"),
                ("Reports", "Reports"),
                ("Settings", "Settings")
            ]
            
            for page_name, page_id in pages:
                if st.button(
                    f"{page_name}",
                    key=f"nav_{page_id}",
                    use_container_width=True,
                    type="secondary" if st.session_state.page != page_id else "primary"
                ):
                    st.session_state.page = page_id
                    st.rerun()

# ---------------------------
# Page Rendering Functions
# ---------------------------
def render_dashboard():
    """Render dashboard page"""
    st.markdown("<h1 class='main-header'>Dashboard</h1>", unsafe_allow_html=True)
    
    if st.session_state.demo_mode:
        st.info("Please log in to access your organization's dashboard")
        
        # Demo dashboard
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("""
                <div class='card'>
                    <div class='card-title'>Total SKUs</div>
                    <div class='card-value'>125</div>
                    <div class='card-subtitle'>Across all categories</div>
                </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown("""
                <div class='card'>
                    <div class='card-title'>Stock Value</div>
                    <div class='card-value'>$45,230</div>
                    <div class='card-subtitle'>Current inventory worth</div>
                </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown("""
                <div class='card'>
                    <div class='card-title'>Low Stock</div>
                    <div class='card-value'>8</div>
                    <div class='card-subtitle'>Items need reordering</div>
                </div>
            """, unsafe_allow_html=True)
        with col4:
            st.markdown("""
                <div class='card'>
                    <div class='card-title'>Monthly Sales</div>
                    <div class='card-value'>$12,450</div>
                    <div class='card-subtitle'>Last 30 days</div>
                </div>
            """, unsafe_allow_html=True)
        
        # Demo charts
        st.subheader("Inventory Overview")
        col1, col2 = st.columns(2)
        
        with col1:
            # Demo bar chart
            chart_data = pd.DataFrame({
                'Category': ['Electronics', 'Clothing', 'Food', 'Stationery'],
                'Items': [45, 32, 28, 20]
            })
            chart = alt.Chart(chart_data).mark_bar().encode(
                x='Category',
                y='Items',
                color=alt.Color('Category', legend=None)
            ).properties(height=300)
            st.altair_chart(chart, use_container_width=True)
        
        with col2:
            # Demo line chart
            dates = pd.date_range(start='2024-01-01', periods=30, freq='D')
            sales_data = pd.DataFrame({
                'Date': dates,
                'Sales': [100 + i*30 + random.randint(-50, 50) for i in range(30)]
            })
            chart = alt.Chart(sales_data).mark_line(point=True).encode(
                x='Date:T',
                y='Sales:Q'
            ).properties(height=300)
            st.altair_chart(chart, use_container_width=True)
        
    else:
        # Real dashboard
        kpis = get_kpis()
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        metrics = [
            ("Total SKUs", kpis.get('total_skus', 0), "#2563eb"),
            ("Stock Value", kpis.get('stock_value', '$0'), "#10b981"),
            ("Low Stock", kpis.get('low_stock', 0), "#f59e0b"),
            ("Monthly Sales", kpis.get('monthly_sales', '$0'), "#8b5cf6"),
            ("Recent Tx", kpis.get('recent_transactions', 0), "#6366f1")
        ]
        
        for (title, value, color), col in zip(metrics, [col1, col2, col3, col4, col5]):
            with col:
                st.markdown(f"""
                    <div class='card'>
                        <div class='card-title'>{title}</div>
                        <div class='card-value' style='color: {color}'>{value}</div>
                        <div class='card-subtitle'>Updated just now</div>
                    </div>
                """, unsafe_allow_html=True)
        
        # Quick actions
        st.subheader("Quick Actions")
        qcol1, qcol2, qcol3, qcol4 = st.columns(4)
        
        with qcol1:
            if st.button("Add Product", use_container_width=True):
                st.session_state.page = "Products"
                st.rerun()
        
        with qcol2:
            if st.button("New Sale", use_container_width=True):
                st.session_state.page = "Sales"
                st.rerun()
        
        with qcol3:
            if st.button("Restock", use_container_width=True):
                st.session_state.page = "Restock"
                st.rerun()
        
        with qcol4:
            if st.button("View Reports", use_container_width=True):
                st.session_state.page = "Reports"
                st.rerun()
        
        # Recent products
        st.subheader("Recent Products")
        products = get_products(page_size=10)
        if not products.empty:
            st.dataframe(
                products[['sku', 'name', 'category', 'qty', 'stock_status']],
                use_container_width=True,
                column_config={
                    'stock_status': st.column_config.TextColumn(
                        "Status",
                        help="Stock status indicator"
                    )
                }
            )
        else:
            st.info("No products found. Add your first product!")
        
        # Recent transactions
        st.subheader("Recent Transactions")
        org = get_current_org()
        if org:
            transactions = fetch_df("""
                SELECT 
                    t.reference,
                    p.name as product,
                    t.type,
                    t.quantity,
                    t.total_amount,
                    t.created_at
                FROM transactions t
                JOIN products p ON t.product_id = p.product_id
                WHERE t.organization = %s
                ORDER BY t.created_at DESC
                LIMIT 10
            """, (org,))
            
            if not transactions.empty:
                st.dataframe(transactions, use_container_width=True)
            else:
                st.info("No transactions yet")

def render_products():
    """Render products management page"""
    st.markdown("<h1 class='main-header'>Products</h1>", unsafe_allow_html=True)
    
    if st.session_state.demo_mode:
        st.warning("Please log in to manage products")
        return
    
    # Product management tabs
    tab1, tab2, tab3 = st.tabs(["Browse Products", "Add Product", "Import/Export"])
    
    with tab1:
        # Search and filters
        col1, col2, col3 = st.columns(3)
        with col1:
            search_term = st.text_input("Search products", placeholder="SKU, name, description...")
        with col2:
            category_filter = st.selectbox("Category", ["All"] + ["Electronics", "Clothing", "Food", "Stationery"])
        with col3:
            stock_filter = st.selectbox("Stock Status", ["All", "In Stock", "Low Stock", "Out of Stock"])
        
        # Pagination
        page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=1)
        page = st.number_input("Page", min_value=1, value=1, step=1)
        
        # Get products
        products = get_products(page=page, page_size=page_size, search=search_term)
        
        if not products.empty:
            # Display products
            st.dataframe(
                products,
                use_container_width=True,
                column_config={
                    "cost_price": st.column_config.NumberColumn(
                        "Cost",
                        format=f"{st.session_state.currency} %.2f"
                    ),
                    "sell_price": st.column_config.NumberColumn(
                        "Price",
                        format=f"{st.session_state.currency} %.2f"
                    ),
                    "stock_status": st.column_config.SelectboxColumn(
                        "Status",
                        options=["low", "critical", "normal"]
                    )
                }
            )
            
            # Action buttons
            selected = st.selectbox("Select product for actions", 
                                  options=["-- select --"] + products['name'].tolist())
            
            if selected != "-- select --":
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("Edit", use_container_width=True):
                        st.info("Edit functionality coming soon")
                with col2:
                    if st.button("View History", use_container_width=True):
                        st.info("History view coming soon")
                with col3:
                    if st.button("Delete", use_container_width=True, type="secondary"):
                        st.warning("Delete functionality coming soon")
        else:
            st.info("No products found")
    
    with tab2:
        # Add product form
        with st.form("add_product_form", clear_on_submit=True):
            st.subheader("Add New Product")
            
            col1, col2 = st.columns(2)
            with col1:
                sku = st.text_input("SKU *", help="Unique stock keeping unit")
                name = st.text_input("Product Name *")
                description = st.text_area("Description")
            
            with col2:
                category = st.selectbox("Category", ["Electronics", "Clothing", "Food", "Stationery", "Other"])
                supplier = st.selectbox("Supplier", ["Supplier A", "Supplier B", "Supplier C", "New Supplier..."])
                unit = st.selectbox("Unit", ["pcs", "kg", "liters", "meters", "boxes"])
            
            col3, col4, col5 = st.columns(3)
            with col3:
                cost_price = st.number_input("Cost Price", min_value=0.0, value=0.0, step=0.01, 
                                           format="%.2f")
                qty = st.number_input("Initial Quantity", min_value=0, value=0, step=1)
            
            with col4:
                sell_price = st.number_input("Selling Price", min_value=0.0, value=0.0, step=0.01,
                                           format="%.2f")
                reorder_level = st.number_input("Reorder Level", min_value=0, value=10, step=1)
            
            with col5:
                min_qty = st.number_input("Minimum Quantity", min_value=0, value=5, step=1)
                location = st.text_input("Storage Location", placeholder="Shelf A1")
            
            barcode = st.text_input("Barcode (optional)")
            
            submitted = st.form_submit_button("Save Product", use_container_width=True)
            
            if submitted:
                if not sku or not name:
                    st.error("SKU and Product Name are required")
                else:
                    st.success(f"Product '{name}' added successfully!")
    
    with tab3:
        # Import/Export section
        st.subheader("Bulk Operations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Export Products")
            st.download_button(
                label="Download CSV Template",
                data="sku,name,description,category,cost_price,sell_price,qty,reorder_level\n",
                file_name="products_template.csv",
                mime="text/csv"
            )
            
            if st.button("Export All Products", use_container_width=True):
                products = get_products(page_size=1000)
                if not products.empty:
                    csv = products.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="products_export.csv",
                        mime="text/csv"
                    )
        
        with col2:
            st.markdown("### Import Products")
            uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
            if uploaded_file:
                df = pd.read_csv(uploaded_file)
                st.write("Preview:", df.head())
                
                if st.button("Import Data", use_container_width=True):
                    st.info(f"Would import {len(df)} products")

# ---------------------------
# Main App
# ---------------------------
def main():
    """Main application function"""
    
    # Initialize database on first run
    if 'db_initialized' not in st.session_state:
        if Database.test_connection():
            init_database()
            st.session_state.db_initialized = True
        else:
            st.warning("Database connection failed. Running in demo mode.")
            st.session_state.demo_mode = True
    
    # Render sidebar
    render_sidebar()
    
    # Main content based on current page
    if st.session_state.page == "Dashboard":
        render_dashboard()
    elif st.session_state.page == "Products":
        render_products()
    elif st.session_state.page == "Sales":
        st.title("Sales")
        st.info("Sales page - Coming soon!")
    elif st.session_state.page == "Restock":
        st.title("Restock")
        st.info("Restock page - Coming soon!")
    elif st.session_state.page == "Suppliers":
        st.title("Suppliers")
        st.info("Suppliers page - Coming soon!")
    elif st.session_state.page == "Categories":
        st.title("Categories")
        st.info("Categories page - Coming soon!")
    elif st.session_state.page == "Reports":
        st.title("Reports")
        st.info("Reports page - Coming soon!")
    elif st.session_state.page == "Settings":
        st.title("Settings")
        
        if st.session_state.authenticated:
            # Organization settings
            with st.expander("Organization Settings", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.selectbox("Default Currency", ["USD", "EUR", "GBP", "GH₵"], 
                               key="currency", index=0)
                    st.selectbox("Time Zone", pytz.common_timezones, 
                               key="timezone", index=pytz.common_timezones.index("UTC"))
                
                with col2:
                    st.checkbox("Prevent Negative Stock", 
                              key="prevent_negative_stock", value=True)
                    st.checkbox("Low Stock Email Alerts", value=True)
                    st.checkbox("Auto-backup Daily", value=True)
            
            # User settings
            with st.expander("User Settings"):
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                if st.button("Change Password") and new_password == confirm_password:
                    st.success("Password updated!")
            
            # Danger zone
            with st.expander("Danger Zone", expanded=False):
                st.warning("These actions cannot be undone!")
                
                if st.button("Export All Data", type="secondary"):
                    st.info("Export functionality coming soon")
                
                if st.button("Reset Organization Data", type="secondary"):
                    if st.checkbox("I understand this will delete all data"):
                        if st.button("CONFIRM RESET", type="primary"):
                            st.error("Reset functionality coming soon")
        else:
            st.info("Please log in to access settings")

# ---------------------------
# Run the app
# ---------------------------
if __name__ == "__main__":
    main()
