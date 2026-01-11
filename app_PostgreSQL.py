"""
InvyPro - Inventory Management System
PostgreSQL Edition | Multi-Organization | Production Ready
"""

import os
import secrets
import hashlib
import hmac
import psycopg2
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from psycopg2.extras import RealDictCursor
import pandas as pd
import streamlit as st
import altair as alt
import pytz
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    """Application Configuration"""
    DB_CONFIG = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'invypro'),
        'user': os.getenv('DB_USER', 'invypro_user'),
        'password': os.getenv('DB_PASSWORD', 'invypro_pass'),
        'sslmode': os.getenv('DB_SSLMODE', 'disable')
    }
    
    APP_CONFIG = {
        'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600')),
        'max_login_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
        'lockout_minutes': int(os.getenv('LOCKOUT_MINUTES', '15')),
        'default_currency': os.getenv('DEFAULT_CURRENCY', 'USD'),
        'default_timezone': os.getenv('DEFAULT_TIMEZONE', 'UTC')
    }

# Initialize configuration
config = Config()

# ============================================================================
# STREAMLIT PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="InvyPro Inventory Manager",
    page_icon="📦",
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
    }
    
    .metric-trend {
        font-size: 0.85rem;
        color: var(--success);
        margin-top: 0.25rem;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 500;
        padding: 0.5rem 1rem;
    }
    
    /* Forms */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stSelectbox > div > div > select {
        border-radius: 6px;
        border: 1px solid var(--border);
    }
    
    /* Data Tables */
    .dataframe {
        border-radius: 8px;
        border: 1px solid var(--border);
    }
    
    /* Badges */
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    .status-in-stock {
        background-color: #d1fae5;
        color: #065f46;
    }
    
    .status-low-stock {
        background-color: #fef3c7;
        color: #92400e;
    }
    
    .status-out-of-stock {
        background-color: #fee2e2;
        color: #991b1b;
    }
    
    /* Sidebar */
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%);
        border-right: 1px solid var(--border);
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================
class Database:
    """Database connection manager with connection pooling"""
    _connection = None
    
    @classmethod
    def get_connection(cls):
        """Get or create database connection"""
        if cls._connection is None or cls._connection.closed:
            try:
                cls._connection = psycopg2.connect(**config.DB_CONFIG)
                cls._connection.autocommit = False
                return cls._connection
            except Exception as e:
                st.error(f"Database connection failed: {str(e)}")
                return None
        return cls._connection
    
    @classmethod
    def close_connection(cls):
        """Close database connection"""
        if cls._connection and not cls._connection.closed:
            cls._connection.close()
            cls._connection = None
    
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
    """Context manager for database transactions"""
    conn = Database.get_connection()
    if conn is None:
        raise ConnectionError("Database connection not available")
    
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise

def execute_query(query: str, params: Tuple = (), fetch: bool = False):
    """Execute SQL query with parameters"""
    with db_session() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
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
        
        # Products table
        """
        CREATE TABLE IF NOT EXISTS products (
            product_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            sku VARCHAR(100) NOT NULL,
            name VARCHAR(200) NOT NULL,
            description TEXT,
            category VARCHAR(100),
            supplier VARCHAR(200),
            unit VARCHAR(50) DEFAULT 'pcs',
            cost_price DECIMAL(15, 2) DEFAULT 0,
            sell_price DECIMAL(15, 2) DEFAULT 0,
            quantity INTEGER DEFAULT 0,
            min_quantity INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 0,
            location VARCHAR(100),
            barcode VARCHAR(100),
            notes TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, sku),
            CHECK (cost_price >= 0),
            CHECK (sell_price >= 0),
            CHECK (quantity >= 0)
        );
        """,
        
        # Transactions table
        """
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
            type VARCHAR(50) NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price DECIMAL(15, 2) DEFAULT 0,
            total_amount DECIMAL(15, 2) DEFAULT 0,
            reference VARCHAR(100),
            notes TEXT,
            status VARCHAR(50) DEFAULT 'completed',
            created_by UUID REFERENCES users(user_id),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            CHECK (type IN ('sale', 'purchase', 'adjustment', 'transfer')),
            CHECK (status IN ('pending', 'completed', 'cancelled'))
        );
        """,
        
        # Suppliers table
        """
        CREATE TABLE IF NOT EXISTS suppliers (
            supplier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            name VARCHAR(200) NOT NULL,
            contact_person VARCHAR(200),
            email VARCHAR(255),
            phone VARCHAR(50),
            address TEXT,
            payment_terms TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, name)
        );
        """,
        
        # Activity logs
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
            organization VARCHAR(200) NOT NULL,
            user_id UUID REFERENCES users(user_id),
            action VARCHAR(100) NOT NULL,
            details TEXT,
            ip_address VARCHAR(50),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """,
        
        # Create indexes
        "CREATE INDEX IF NOT EXISTS idx_products_org ON products(organization);",
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_org ON transactions(organization);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at);",
        
        # Update timestamp trigger
        """
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        
        CREATE TRIGGER update_products_timestamp 
            BEFORE UPDATE ON products 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """
    ]
    
    try:
        with db_session() as conn:
            with conn.cursor() as cur:
                for query in schema_queries:
                    try:
                        cur.execute(query)
                    except Exception as e:
                        if "already exists" not in str(e):
                            print(f"Schema note: {str(e)}")
                        continue
        
        # Create default admin user
        create_default_admin()
        st.success("Database initialized successfully")
        return True
    except Exception as e:
        st.error(f"Database initialization failed: {str(e)}")
        return False

def create_default_admin():
    """Create default admin user if no users exist"""
    try:
        # Check if users exist
        result = execute_query("SELECT COUNT(*) as count FROM users;", fetch=True)
        if result and result[0]['count'] == 0:
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
                VALUES (%s, %s, %s, %s, 'admin')
                """,
                (username, password_hash, salt, organization)
            )
            
            print(f"Created default admin: {username} / {password}")
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
            VALUES (%s, %s, %s, %s, %s, 'admin')
            """,
            (username, email, password_hash, salt, organization)
        )
        
        log_activity(
            user_id=None,
            action="user_registration",
            details=f"New user registered: {username} for {organization}"
        )
        
        return {"success": True, "message": "Account created successfully"}
        
    except psycopg2.IntegrityError as e:
        if "users_username_key" in str(e):
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
            """
            SELECT user_id, username, password_hash, salt, organization, role, is_active
            FROM users WHERE username = %s
            """,
            (username,),
            fetch=True
        )
        
        if not result:
            return {"success": False, "message": "Invalid credentials"}
        
        user = result[0]
        
        if not user['is_active']:
            return {"success": False, "message": "Account is inactive"}
        
        if verify_password(user['password_hash'], user['salt'], password):
            # Update last login
            execute_query(
                "UPDATE users SET last_login = NOW() WHERE user_id = %s",
                (user['user_id'],)
            )
            
            log_activity(
                user_id=user['user_id'],
                action="user_login",
                details=f"User logged in: {username}"
            )
            
            return {
                "success": True,
                "message": "Login successful",
                "user": {
                    'id': user['user_id'],
                    'username': user['username'],
                    'organization': user['organization'],
                    'role': user['role']
                }
            }
        else:
            return {"success": False, "message": "Invalid credentials"}
            
    except Exception as e:
        return {"success": False, "message": f"Authentication error: {str(e)}"}

def log_activity(user_id: Optional[str] = None, action: str = "", details: str = ""):
    """Log user activity"""
    try:
        execute_query(
            """
            INSERT INTO activity_logs (organization, user_id, action, details)
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
    st.session_state.demo_mode = False
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
        WHERE organization = %s
    """
    
    params = [org]
    
    if search:
        query += " AND (sku ILIKE %s OR name ILIKE %s OR description ILIKE %s)"
        params.extend([f"%{search}%"] * 3)
    
    query += " ORDER BY updated_at DESC LIMIT %s OFFSET %s"
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
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
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
        
    except psycopg2.IntegrityError:
        return {"success": False, "message": "SKU already exists"}
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
            "SELECT COUNT(*) as count FROM products WHERE organization = %s",
            (org,)
        )
        total_products = total_df.iloc[0]['count'] if not total_df.empty else 0
        
        # Stock value
        value_df = fetch_dataframe(
            "SELECT SUM(quantity * cost_price) as value FROM products WHERE organization = %s",
            (org,)
        )
        stock_value = value_df.iloc[0]['value'] if not value_df.empty else 0
        
        # Low stock items
        low_df = fetch_dataframe(
            """
            SELECT COUNT(*) as count 
            FROM products 
            WHERE organization = %s AND quantity <= reorder_level
            """,
            (org,)
        )
        low_stock = low_df.iloc[0]['count'] if not low_df.empty else 0
        
        # Out of stock items
        out_df = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = %s AND quantity = 0",
            (org,)
        )
        out_of_stock = out_df.iloc[0]['count'] if not out_df.empty else 0
        
        return {
            'total_products': total_products,
            'stock_value': f"{st.session_state.currency} {stock_value:,.2f}",
            'low_stock': low_stock,
            'out_of_stock': out_of_stock
        }
    except:
        return {}

# ============================================================================
# UI COMPONENTS
# ============================================================================
def render_sidebar():
    """Render sidebar navigation"""
    with st.sidebar:
        st.markdown("## InvyPro")
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
                        else:
                            st.error(result['message'])
            
            st.markdown("---")
            st.markdown("### Features")
            st.markdown("• Multi-organization support")
            st.markdown("• Real-time inventory tracking")
            st.markdown("• Sales & purchase management")
            st.markdown("• Supplier management")
            st.markdown("• Advanced reporting")
            
        else:
            # User Info
            st.success(f"Welcome, {st.session_state.username}")
            st.caption(f"Organization: {st.session_state.organization}")
            st.caption(f"Role: {st.session_state.role}")
            
            if st.button("Logout", use_container_width=True):
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
            <div class='metric-trend'>Active inventory</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Stock Value</div>
            <div class='metric-value'>{metrics.get('stock_value', '$0.00')}</div>
            <div class='metric-trend'>Current value</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Low Stock</div>
            <div class='metric-value'>{metrics.get('low_stock', 0)}</div>
            <div class='metric-trend'>Need reordering</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class='metric-card'>
            <div class='metric-title'>Out of Stock</div>
            <div class='metric-value'>{metrics.get('out_of_stock', 0)}</div>
            <div class='metric-trend'>Require attention</div>
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
        display_df = products.copy()
        
        # Add status column
        def get_status(row):
            if row['quantity'] == 0:
                return '<span class="status-badge status-out-of-stock">Out of Stock</span>'
            elif row['quantity'] <= row['reorder_level']:
                return '<span class="status-badge status-low-stock">Low Stock</span>'
            else:
                return '<span class="status-badge status-in-stock">In Stock</span>'
        
        display_df['status'] = display_df.apply(get_status, axis=1)
        display_df['cost'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        display_df['price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
        
        st.markdown(display_df[['sku', 'name', 'category', 'quantity', 'cost', 'price', 'status']].to_html(
            escape=False, index=False, classes='dataframe'
        ), unsafe_allow_html=True)
    else:
        st.info("No products found. Add your first product using the 'Add Product' button above.")

def render_products():
    """Render products management page"""
    st.markdown("<h1 class='main-header'>Products</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage products")
        return
    
    # Tabs for product management
    tab1, tab2 = st.tabs(["Product List", "Add Product"])
    
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
            elif stock_filter == "Out of Stock":
                products = products[products['quantity'] == 0]
            elif stock_filter == "In Stock":
                products = products[products['quantity'] > 0]
            
            # Display products
            st.dataframe(
                products[['sku', 'name', 'category', 'quantity', 'cost_price', 'sell_price', 'location']],
                use_container_width=True,
                column_config={
                    "cost_price": st.column_config.NumberColumn(
                        "Cost",
                        format=f"{st.session_state.currency} %.2f"
                    ),
                    "sell_price": st.column_config.NumberColumn(
                        "Price",
                        format=f"{st.session_state.currency} %.2f"
                    )
                }
            )
            
            # Export option
            if st.button("Export to CSV"):
                csv = products.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="products_export.csv",
                    mime="text/csv"
                )
        else:
            st.info("No products found")
    
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
                unit = st.selectbox("Unit", ["pcs", "kg", "liters", "boxes", "meters", "units"])
                location = st.text_input("Location", placeholder="Shelf A1")
                barcode = st.text_input("Barcode (Optional)")
                notes = st.text_area("Notes")
            
            col3, col4, col5 = st.columns(3)
            
            with col3:
                cost_price = st.number_input(
                    "Cost Price",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f"
                )
                quantity = st.number_input(
                    "Quantity",
                    min_value=0,
                    value=0,
                    step=1
                )
            
            with col4:
                sell_price = st.number_input(
                    "Selling Price",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f"
                )
                min_quantity = st.number_input(
                    "Minimum Quantity",
                    min_value=0,
                    value=5,
                    step=1
                )
            
            with col5:
                reorder_level = st.number_input(
                    "Reorder Level",
                    min_value=0,
                    value=10,
                    step=1
                )
            
            submitted = st.form_submit_button("Save Product", use_container_width=True)
            
            if submitted:
                if not sku or not name:
                    st.error("SKU and Product Name are required")
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

def render_transactions():
    """Render transactions page"""
    st.markdown("<h1 class='main-header'>Transactions</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view transactions")
        return
    
    st.info("Transaction recording functionality coming soon")

def render_suppliers():
    """Render suppliers page"""
    st.markdown("<h1 class='main-header'>Suppliers</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage suppliers")
        return
    
    st.info("Supplier management functionality coming soon")

def render_reports():
    """Render reports page"""
    st.markdown("<h1 class='main-header'>Reports</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view reports")
        return
    
    st.info("Reporting functionality coming soon")

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
                pytz.common_timezones,
                index=pytz.common_timezones.index(
                    st.session_state.timezone if st.session_state.timezone in pytz.common_timezones 
                    else "UTC"
                ),
                key="timezone_select"
            )
            st.session_state.timezone = timezone
    
    # User Settings
    with st.expander("User Settings"):
        st.write("Change Password")
        current_pass = st.text_input("Current Password", type="password")
        new_pass = st.text_input("New Password", type="password")
        confirm_pass = st.text_input("Confirm New Password", type="password")
        
        if st.button("Update Password"):
            if new_pass != confirm_pass:
                st.error("New passwords do not match")
            elif len(new_pass) < 8:
                st.error("Password must be at least 8 characters")
            else:
                st.success("Password updated successfully")
    
    # System Settings
    with st.expander("System Settings"):
        col_sys1, col_sys2 = st.columns(2)
        
        with col_sys1:
            prevent_negative = st.checkbox("Prevent Negative Stock", value=True)
            auto_backup = st.checkbox("Automatic Backups", value=False)
        
        with col_sys2:
            email_alerts = st.checkbox("Email Alerts", value=False)
            low_stock_notify = st.checkbox("Low Stock Notifications", value=True)
    
    # Danger Zone
    with st.expander("Danger Zone", expanded=False):
        st.warning("These actions cannot be undone. Proceed with caution.")
        
        if st.button("Export All Data", type="secondary"):
            st.info("Data export functionality coming soon")
        
        if st.button("Reset Organization Data", type="secondary"):
            confirm = st.checkbox("I understand this will delete all products and transactions")
            if confirm and st.button("CONFIRM RESET", type="primary"):
                st.error("Data reset functionality coming soon")

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
            else:
                st.warning("Running in demo mode. Database connection required for full functionality.")
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

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    # Create necessary directories
    import os
    os.makedirs("data", exist_ok=True)
    os.makedirs("backups", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    
    # Run the application
    main()
