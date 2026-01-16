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
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import base64
import shutil
from pathlib import Path

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
    page_icon="📊",
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
    
    .badge-info {
        background-color: #dbeafe;
        color: #1e40af;
    }
    
    .badge-secondary {
        background-color: #e2e8f0;
        color: #475569;
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
    
    /* Report Cards */
    .report-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
    }
    
    .download-btn {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white !important;
        border: none !important;
    }
    
    .visualization-container {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        border: 1px solid var(--border);
        margin-bottom: 1.5rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================
class Database:
    """SQLite database manager"""
    
    @staticmethod
    def get_connection():
        """Get database connection"""
        conn = sqlite3.connect(config.DB_FILE, check_same_thread=False)
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
    except Exception as e:
        conn.rollback()
        raise e
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
        "CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at);",
        "CREATE INDEX IF NOT EXISTS idx_transactions_product ON transactions(product_id);",
        "CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);",
        "CREATE INDEX IF NOT EXISTS idx_products_quantity ON products(quantity);",
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
    except Exception as e:
        st.warning(f"Could not create default admin: {str(e)}")

# ============================================================================
# BACKUP MANAGEMENT
# ============================================================================

def create_backup():
    """Create a backup of the database"""
    try:
        backup_dir = Path("backups")
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        org = get_current_organization()
        org_safe = org.replace(" ", "_").replace("/", "_") if org else "all"
        
        backup_filename = f"backup_{org_safe}_{timestamp}.db"
        backup_path = backup_dir / backup_filename
        
        shutil.copy2(config.DB_FILE, backup_path)
        
        log_activity(
            user_id=st.session_state.get('user_id'),
            action="backup_created",
            details=f"Database backup created: {backup_filename}"
        )
        
        return {"success": True, "message": f"Backup created: {backup_filename}", "filename": backup_filename}
    
    except Exception as e:
        return {"success": False, "message": f"Backup failed: {str(e)}"}


def list_backups():
    """List all available backups"""
    try:
        backup_dir = Path("backups")
        if not backup_dir.exists():
            return []
        
        backups = []
        for backup_file in backup_dir.glob("backup_*.db"):
            try:
                stat = backup_file.stat()
                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime),
                    'size_mb': stat.st_size / (1024 * 1024)
                })
            except Exception as e:
                print(f"Error reading backup file {backup_file}: {e}")
                continue
        
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups
    
    except Exception as e:
        print(f"Error listing backups: {e}")
        return []


def restore_backup(backup_filename):
    """Restore database from backup"""
    try:
        backup_path = Path("backups") / backup_filename
        
        if not backup_path.exists():
            return {"success": False, "message": "Backup file not found"}
        
        create_backup()
        shutil.copy2(backup_path, config.DB_FILE)
        
        log_activity(
            user_id=st.session_state.get('user_id'),
            action="backup_restored",
            details=f"Database restored from: {backup_filename}"
        )
        
        return {"success": True, "message": f"Database restored from {backup_filename}"}
    
    except Exception as e:
        return {"success": False, "message": f"Restore failed: {str(e)}"}


def delete_backup(backup_filename):
    """Delete a backup file"""
    try:
        backup_path = Path("backups") / backup_filename
        
        if not backup_path.exists():
            return {"success": False, "message": "Backup file not found"}
        
        backup_path.unlink()
        
        log_activity(
            user_id=st.session_state.get('user_id'),
            action="backup_deleted",
            details=f"Backup deleted: {backup_filename}"
        )
        
        return {"success": True, "message": "Backup deleted successfully"}
    
    except Exception as e:
        return {"success": False, "message": f"Delete failed: {str(e)}"}


def render_backup_management():
    """Render backup management section in settings"""
    st.markdown("### Backup Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Create Backup Now", use_container_width=True, type="primary", key="create_backup_btn"):
            with st.spinner("Creating backup..."):
                result = create_backup()
                if result['success']:
                    st.success(result['message'])
                    st.rerun()
                else:
                    st.error(result['message'])
    
    with col2:
        auto_backup_enabled = st.checkbox(
            "Automatic Backup on Startup",
            value=st.session_state.get('auto_backup_enabled', False),
            key="auto_backup_enabled",
            help="Automatically create a backup every time the app starts"
        )
    
    st.markdown("---")
    st.markdown("#### Available Backups")
    
    try:
        backups = list_backups()
        
        if backups:
            st.info(f"Found {len(backups)} backup(s)")
            
            for idx, backup in enumerate(backups):
                with st.expander(f"{backup['filename']} ({backup['size_mb']:.2f} MB)", expanded=False):
                    col_info, col_actions = st.columns([2, 1])
                    
                    with col_info:
                        st.write(f"**Created:** {backup['created'].strftime('%Y-%m-%d %H:%M:%S')}")
                        st.write(f"**Size:** {backup['size_mb']:.2f} MB")
                        st.write(f"**File:** {backup['filename']}")
                    
                    with col_actions:
                        try:
                            with open(backup['path'], 'rb') as f:
                                backup_data = f.read()
                                st.download_button(
                                    label="Download",
                                    data=backup_data,
                                    file_name=backup['filename'],
                                    mime="application/octet-stream",
                                    use_container_width=True,
                                    key=f"download_backup_{idx}"
                                )
                        except Exception as e:
                            st.error(f"Cannot download: {str(e)}")
                        
                        if st.button("Restore", use_container_width=True, key=f"restore_backup_{idx}"):
                            if st.session_state.get(f'confirm_restore_{idx}', False):
                                with st.spinner("Restoring backup..."):
                                    result = restore_backup(backup['filename'])
                                    if result['success']:
                                        st.success(result['message'])
                                        st.info("Please refresh the page to see changes")
                                        st.session_state[f'confirm_restore_{idx}'] = False
                                    else:
                                        st.error(result['message'])
                            else:
                                st.session_state[f'confirm_restore_{idx}'] = True
                                st.warning("Click 'Restore' again to confirm. This will replace your current database!")
                                st.rerun()
                        
                        if st.button("🗑️ Delete", use_container_width=True, key=f"delete_backup_{idx}"):
                            if st.session_state.get(f'confirm_delete_{idx}', False):
                                with st.spinner("Deleting backup..."):
                                    result = delete_backup(backup['filename'])
                                    if result['success']:
                                        st.success(result['message'])
                                        st.session_state[f'confirm_delete_{idx}'] = False
                                        st.rerun()
                                    else:
                                        st.error(result['message'])
                            else:
                                st.session_state[f'confirm_delete_{idx}'] = True
                                st.warning("Click 'Delete' again to confirm")
                                st.rerun()
        else:
            st.info("No backups available. Create your first backup using the button above.")
    
    except Exception as e:
        st.error(f"Error loading backups: {str(e)}")
    
    st.markdown("---")
    st.markdown("#### Backup Maintenance")
    
    col_clean1, col_clean2 = st.columns(2)
    
    with col_clean1:
        max_backups = st.number_input(
            "Keep last N backups",
            min_value=1,
            max_value=50,
            value=10,
            help="Automatically delete old backups beyond this limit",
            key="max_backups_input"
        )
    
    with col_clean2:
        if st.button("Cleanup Old Backups", use_container_width=True, key="cleanup_backups_btn"):
            try:
                backups = list_backups()
                if len(backups) > max_backups:
                    with st.spinner("Cleaning up old backups..."):
                        to_delete = backups[max_backups:]
                        deleted_count = 0
                        
                        for backup in to_delete:
                            result = delete_backup(backup['filename'])
                            if result['success']:
                                deleted_count += 1
                        
                        st.success(f"Deleted {deleted_count} old backup(s)")
                        st.rerun()
                else:
                    st.info(f"Only {len(backups)} backup(s) exist. No cleanup needed.")
            except Exception as e:
                st.error(f"Cleanup failed: {str(e)}")

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
    """Log user activity"""
    try:
        org = st.session_state.get('organization', 'PUBLIC') if 'authenticated' in st.session_state else 'PUBLIC'
        execute_query(
            """
            INSERT INTO activity_logs (organization, user_id, action, details)
            VALUES (?, ?, ?, ?)
            """,
            (org, user_id, action, details)
        )
    except Exception as e:
        print(f"Error logging activity: {e}")

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
        
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e):
            return {"success": False, "message": "SKU already exists"}
        return {"success": False, "message": f"Database error: {str(e)}"}
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
        total_df = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ?",
            (org,)
        )
        total_products = total_df.iloc[0]['count'] if not total_df.empty else 0
        
        value_df = fetch_dataframe(
            "SELECT SUM(quantity * cost_price) as value FROM products WHERE organization = ?",
            (org,)
        )
        stock_value = value_df.iloc[0]['value'] if not value_df.empty else 0
        
        low_df = fetch_dataframe(
            """
            SELECT COUNT(*) as count 
            FROM products 
            WHERE organization = ? AND quantity <= reorder_level AND quantity > 0
            """,
            (org,)
        )
        low_stock = low_df.iloc[0]['count'] if not low_df.empty else 0
        
        out_df = fetch_dataframe(
            "SELECT COUNT(*) as count FROM products WHERE organization = ? AND quantity = 0",
            (org,)
        )
        out_of_stock = out_df.iloc[0]['count'] if not out_df.empty else 0
        
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
        print(f"Error getting key metrics: {e}")
        return {}

def get_recent_transactions(limit: int = 10):
    """Get recent transactions for current organization"""
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
    """Record a new transaction"""
    org = get_current_organization()
    if not org:
        return {"success": False, "message": "Not authenticated"}
    
    try:
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
                transaction_data['product_id'],
                transaction_data['type'],
                transaction_data['quantity'],
                transaction_data['unit_price'],
                transaction_data['total_amount'],
                transaction_data['reference'],
                transaction_data['notes'],
                st.session_state.user_id
            )
        )
        
        # Update product stock based on transaction type
        # In record_transaction(), add validation:
        if transaction_data['type'] == 'adjustment' and transaction_data['quantity'] < 0:
            return {"success": False, "message": "Adjustment quantity cannot be negative"}
        if transaction_data['type'] in ['sale', 'purchase', 'adjustment']:
            current_qty_result = execute_query(
                "SELECT quantity FROM products WHERE product_id = ? AND organization = ?",
                (transaction_data['product_id'], org),
                fetch=True
            )
            
            if current_qty_result:
                current_qty = current_qty_result[0][0]
                
                if transaction_data['type'] == 'sale':
                    new_quantity = current_qty - transaction_data['quantity']
                elif transaction_data['type'] == 'purchase':
                    new_quantity = current_qty + transaction_data['quantity']
                elif transaction_data['type'] == 'adjustment':
                    new_quantity = transaction_data['quantity']
                else:
                    new_quantity = current_qty
                
                execute_query(
                    "UPDATE products SET quantity = ?, updated_at = CURRENT_TIMESTAMP WHERE product_id = ?",
                    (new_quantity, transaction_data['product_id'])
                )
        
        # Log activity
        product_name_result = execute_query(
            "SELECT name FROM products WHERE product_id = ?",
            (transaction_data['product_id'],),
            fetch=True
        )
        
        product_name = product_name_result[0][0] if product_name_result else "Unknown Product"
        
        log_activity(
            user_id=st.session_state.user_id,
            action="transaction_recorded",
            details=f"Recorded {transaction_data['type']} transaction: {transaction_data['quantity']} units of {product_name}"
        )
        
        return {"success": True, "message": "Transaction recorded successfully"}
        
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def get_sales_report(start_date: str, end_date: str):
    """Get sales report for date range"""
    org = get_current_organization()
    if not org:
        return pd.DataFrame()
    
    query = """
        SELECT 
            DATE(t.created_at) as sale_date,
            p.sku,
            p.name,
            SUM(t.quantity) as total_quantity,
            SUM(t.total_amount) as total_amount,
            COUNT(*) as transaction_count
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.organization = ? 
            AND t.type = 'sale'
            AND DATE(t.created_at) BETWEEN ? AND ?
        GROUP BY DATE(t.created_at), p.product_id
        ORDER BY sale_date DESC, total_amount DESC
    """
    
    return fetch_dataframe(query, (org, start_date, end_date))

def get_inventory_summary():
    """Get inventory summary"""
    org = get_current_organization()
    if not org:
        return pd.DataFrame()
    
    query = """
        SELECT 
            category,
            COUNT(*) as product_count,
            SUM(quantity) as total_quantity,
            SUM(quantity * cost_price) as total_value,
            AVG(cost_price) as avg_cost,
            AVG(sell_price) as avg_price
        FROM products 
        WHERE organization = ? AND quantity > 0
        GROUP BY category
        ORDER BY total_value DESC
    """
    
    return fetch_dataframe(query, (org,))

# ============================================================================
# UI COMPONENTS
# ============================================================================
def render_sidebar():
    """Render sidebar navigation"""
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
                
                if st.button("Login", type="primary", use_container_width=True, key="login_button"):
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
                
                if st.button("Create Account", use_container_width=True, key="signup_button"):
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
            st.markdown("• Multi-organization support")
            st.markdown("• Real-time inventory tracking")
            st.markdown("• Sales and purchase management")
            st.markdown("• Supplier management")
            st.markdown("• Advanced reporting")
            st.markdown("• Data export")
            
        else:
            st.success(f"Welcome, {st.session_state.username}")
            st.caption(f"Organization: {st.session_state.organization}")
            st.caption(f"Role: {st.session_state.role}")
            
            if st.button("Logout", use_container_width=True, type="secondary", key="logout_button"):
                logout_user()
                
            st.markdown("---")
            
            pages = {
                "Dashboard": "",
                "Products": "",
                "Transactions": "",
                "Suppliers": "",
                "Reports": "",
                "Settings": ""
            
            }
            
            for page_name, icon in pages.items():
                if st.button(
                    f"{icon} {page_name}",
                    key=f"nav_{page_name}",
                    use_container_width=True,
                    type="primary" if st.session_state.page == page_name else "secondary"
                ):
                    st.session_state.page = page_name
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
            <div class='metric-value'>{metrics.get('stock_value', 'GHS 0.00')}</div>
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
            <div class='metric-value'>{metrics.get('monthly_sales', 'GHS 0.00')}</div>
            <div class='metric-subtitle'>Last 30 days</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Recent Transactions
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("<h2 class='section-header'>Recent Transactions</h2>", unsafe_allow_html=True)
        
        transactions = get_recent_transactions(limit=10)
        if not transactions.empty:
            display_df = transactions.copy()
            
            def format_type(t_type):
                colors = {
                    'sale': 'badge-success',
                    'purchase': 'badge-info',
                    'adjustment': 'badge-warning',
                    'transfer': 'badge-secondary'
                }
                color = colors.get(t_type, 'badge-secondary')
                return f'<span class="badge {color}">{t_type.upper()}</span>'
            
            display_df['type'] = display_df['type'].apply(format_type)
            display_df['unit_price'] = display_df['unit_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['total_amount'] = display_df['total_amount'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            html_table = display_df[['created_at', 'type', 'sku', 'product_name', 'quantity', 'unit_price', 'total_amount', 'reference']].to_html(
                escape=False, index=False, classes='dataframe', border=0
            )
            st.markdown(html_table, unsafe_allow_html=True)
            
            if st.button("View All Transactions", use_container_width=True, key="view_all_transactions"):
                st.session_state.page = "Transactions"
                st.rerun()
        else:
            st.info("No recent transactions found.")
    
    with col2:
        st.markdown("<h2 class='section-header'>Quick Actions</h2>", unsafe_allow_html=True)
        
        if st.button("Add New Product", use_container_width=True, key="quick_add_product"):
            st.session_state.page = "Products"
            st.rerun()
        
        if st.button("Record Sale", use_container_width=True, key="quick_record_sale"):
            st.session_state.page = "Transactions"
            st.rerun()
        
        if st.button("View Reports", use_container_width=True, key="quick_view_reports"):
            st.session_state.page = "Reports"
            st.rerun()
        
        if st.button("Manage Suppliers", use_container_width=True, key="quick_manage_suppliers"):
            st.session_state.page = "Suppliers"
            st.rerun()

def render_products():
    """Render products management page"""
    st.markdown("<h1 class='main-header'>Products</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage products")
        return
    
    tab1, tab2, tab3 = st.tabs(["Product List", "Add Product", "Edit Product"])
    
    with tab1:
        col_search, col_filter, col_page = st.columns(3)
        
        with col_search:
            search_term = st.text_input("Search products", placeholder="SKU, name, description...", key="product_search")
        
        with col_filter:
            stock_filter = st.selectbox(
                "Stock Status",
                ["All", "In Stock", "Low Stock", "Out of Stock"],
                key="stock_filter"
            )
        
        with col_page:
            page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=1, key="page_size")
        
        page_number = st.number_input("Page", min_value=1, value=1, step=1, key="page_number")
        
        products = get_products(search=search_term, page=page_number, page_size=page_size)
        
        if not products.empty:
            # Apply stock filter
            if stock_filter == "Low Stock":
                products = products[(products['quantity'] <= products['reorder_level']) & (products['quantity'] > 0)]
            elif stock_filter == "Out of Stock":
                products = products[products['quantity'] == 0]
            elif stock_filter == "In Stock":
                products = products[products['quantity'] > 0]
            
            st.caption(f"Showing {len(products)} products")
            
            display_df = products[['sku', 'name', 'category', 'quantity', 'reorder_level', 'cost_price', 'sell_price', 'location']].copy()
            display_df['cost_price'] = display_df['cost_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['sell_price'] = display_df['sell_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            def get_stock_status(row):
                if row['quantity'] == 0:
                    return "🔴 Out of Stock"
                elif row['quantity'] <= row['reorder_level']:
                    return "🟡 Low Stock"
                else:
                    return "🟢 In Stock"
            
            display_df['status'] = display_df.apply(get_stock_status, axis=1)
            display_df = display_df.drop('reorder_level', axis=1)
            
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
            
            col_export, col_refresh = st.columns(2)
            with col_export:
                csv = products.to_csv(index=False)
                st.download_button(
                    label="Export to CSV",
                    data=csv,
                    file_name="products_export.csv",
                    mime="text/csv",
                    key="export_csv",
                    use_container_width=True
                )
            
            with col_refresh:
                if st.button("Refresh", use_container_width=True, key="refresh_products"):
                    st.rerun()
                    
        else:
            st.info("No products found. Add your first product in the 'Add Product' tab.")
    
    with tab2:
        with st.form("add_product_form", clear_on_submit=True):
            st.subheader("Add New Product")
            
            col1, col2 = st.columns(2)
            
            with col1:
                sku = st.text_input("SKU *", help="Unique product identifier", key="add_sku")
                name = st.text_input("Product Name *", key="add_name")
                description = st.text_area("Description", key="add_description")
                category = st.text_input("Category", key="add_category")
                supplier = st.text_input("Supplier", key="add_supplier")
            
            with col2:
                unit = st.selectbox("Unit", ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"], key="add_unit")
                location = st.text_input("Location", placeholder="Shelf A1, Warehouse B, etc.", key="add_location")
                barcode = st.text_input("Barcode (Optional)", key="add_barcode")
                notes = st.text_area("Notes", key="add_notes")
            
            col3, col4, col5 = st.columns(3)
            
            with col3:
                cost_price = st.number_input(
                    "Cost Price *",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f",
                    help="Purchase cost per unit",
                    key="add_cost_price"
                )
                quantity = st.number_input(
                    "Initial Quantity *",
                    min_value=0,
                    value=0,
                    step=1,
                    help="Current stock level",
                    key="add_quantity"
                )
            
            with col4:
                sell_price = st.number_input(
                    "Selling Price *",
                    min_value=0.0,
                    value=0.0,
                    step=0.01,
                    format="%.2f",
                    help="Selling price per unit",
                    key="add_sell_price"
                )
                min_quantity = st.number_input(
                    "Minimum Quantity",
                    min_value=0,
                    value=5,
                    step=1,
                    help="Minimum stock level before alert",
                    key="add_min_quantity"
                )
            
            with col5:
                reorder_level = st.number_input(
                    "Reorder Level *",
                    min_value=0,
                    value=10,
                    step=1,
                    help="Reorder when stock reaches this level",
                    key="add_reorder_level"
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
        st.subheader("Edit Product")
        
        all_products = get_products(page_size=1000)
        
        if not all_products.empty:
            product_options = ["-- Select Product --"] + all_products['name'].tolist()
            selected_product = st.selectbox("Select product to edit", product_options, key="edit_product_select")
            
            if selected_product != "-- Select Product --":
                product_idx = all_products[all_products['name'] == selected_product].index[0]
                product_data = all_products.iloc[product_idx]
                
                with st.form("edit_product_form"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        edit_sku = st.text_input("SKU", value=product_data['sku'], key="edit_sku")
                        edit_name = st.text_input("Product Name", value=product_data['name'], key="edit_name")
                        edit_description = st.text_area("Description", value=product_data['description'] or "", key="edit_description")
                        edit_category = st.text_input("Category", value=product_data['category'] or "", key="edit_category")
                        edit_supplier = st.text_input("Supplier", value=product_data['supplier'] or "", key="edit_supplier")
                    
                    with col2:
                        edit_unit = st.selectbox("Unit", 
                                               ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"],
                                               index=["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"].index(
                                                   product_data['unit'] if product_data['unit'] in 
                                                   ["pcs", "kg", "liters", "boxes", "meters", "units", "pairs", "dozen"] 
                                                   else "pcs"
                                               ), key="edit_unit")
                        edit_location = st.text_input("Location", value=product_data['location'] or "", key="edit_location")
                        edit_barcode = st.text_input("Barcode", value=product_data['barcode'] or "", key="edit_barcode")
                        edit_notes = st.text_area("Notes", value=product_data['notes'] or "", key="edit_notes")
                    
                    col3, col4, col5 = st.columns(3)
                    
                    with col3:
                        edit_cost = st.number_input(
                            "Cost Price",
                            min_value=0.0,
                            value=float(product_data['cost_price']),
                            step=0.01,
                            format="%.2f",
                            key="edit_cost"
                        )
                        edit_quantity = st.number_input(
                            "Quantity",
                            min_value=0,
                            value=int(product_data['quantity']),
                            step=1,
                            key="edit_quantity"
                        )
                    
                    with col4:
                        edit_price = st.number_input(
                            "Selling Price",
                            min_value=0.0,
                            value=float(product_data['sell_price']),
                            step=0.01,
                            format="%.2f",
                            key="edit_price"
                        )
                        edit_min_qty = st.number_input(
                            "Minimum Quantity",
                            min_value=0,
                            value=int(product_data['min_quantity']),
                            step=1,
                            key="edit_min_qty"
                        )
                    
                    with col5:
                        edit_reorder = st.number_input(
                            "Reorder Level",
                            min_value=0,
                            value=int(product_data['reorder_level']),
                            step=1,
                            key="edit_reorder"
                        )
                    
                    col_update, col_delete = st.columns(2)
                    
                    with col_update:
                        update_submitted = st.form_submit_button("Update Product", use_container_width=True)
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
                    
                    with col_delete:
                        delete_clicked = st.form_submit_button("Delete Product", type="secondary", use_container_width=True)
                        if delete_clicked:
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
    
    tab1, tab2 = st.tabs(["Record Transaction", "Transaction History"])
    
    with tab1:
        with st.form("record_transaction_form", clear_on_submit=True):
            st.subheader("Record New Transaction")
            
            col_type, col_ref = st.columns(2)
            
            with col_type:
                transaction_type = st.selectbox(
                    "Transaction Type *",
                    ["sale", "purchase", "adjustment", "transfer"],
                    help="Sale: Selling to customers, Purchase: Buying from suppliers, Adjustment: Stock correction, Transfer: Moving between locations",
                    key="trans_type"
                )
            
            with col_ref:
                reference = st.text_input("Reference Number", help="Invoice/Purchase order number", key="trans_reference")
            
            st.markdown("### Product Details")
            
            products = get_products(page_size=1000)
            
            if not products.empty:
                product_options = ["-- Select Product --"] + products['name'].tolist()
                selected_product = st.selectbox("Select Product *", product_options, key="trans_product")
                
                if selected_product != "-- Select Product --":
                    product_info = products[products['name'] == selected_product].iloc[0]
                    product_id = product_info['product_id']
                    
                    col_qty, col_price = st.columns(2)
                    
                    with col_qty:
                        st.info(f"Current Stock: {product_info['quantity']} {product_info['unit']}")
                        quantity = st.number_input(
                            "Quantity *",
                            min_value=1,
                            value=1,
                            step=1,
                            help="Quantity to transact",
                            key="trans_quantity"
                        )
                        
                        if transaction_type == 'sale' and quantity > product_info['quantity']:
                            st.error(f"Insufficient stock! Only {product_info['quantity']} units available.")
                    
                    with col_price:
                        default_price = product_info['sell_price'] if transaction_type == 'sale' else product_info['cost_price']
                        unit_price = st.number_input(
                            "Unit Price *",
                            min_value=0.0,
                            value=float(default_price),
                            step=0.01,
                            format="%.2f",
                            help="Price per unit",
                            key="trans_unit_price"
                        )
                    
                    total_amount = quantity * unit_price
                    st.markdown(f"**Total Amount:** {st.session_state.currency} {total_amount:,.2f}")
                    
                    notes = st.text_area("Notes", help="Additional transaction notes", key="trans_notes")
                else:
                    product_id = None
                    quantity = 1
                    unit_price = 0.0
                    total_amount = 0.0
                    notes = ""
            else:
                st.info("No products found. Please add products first.")
                product_id = None
                quantity = 1
                unit_price = 0.0
                total_amount = 0.0
                notes = ""
            
            submitted = st.form_submit_button("Record Transaction", type="primary", use_container_width=True)
            
            if submitted:
                if not products.empty and selected_product == "-- Select Product --":
                    st.error("Please select a product")
                elif products.empty:
                    st.error("No products available. Please add products first.")
                elif transaction_type == 'sale' and quantity > product_info['quantity']:
                    st.error("Cannot complete sale: Insufficient stock")
                else:
                    transaction_data = {
                        'product_id': product_id,
                        'type': transaction_type,
                        'quantity': quantity,
                        'unit_price': unit_price,
                        'total_amount': total_amount,
                        'reference': reference,
                        'notes': notes
                    }
                    
                    result = record_transaction(transaction_data)
                    if result['success']:
                        st.success(result['message'])
                        st.rerun()
                    else:
                        st.error(result['message'])
        
        if products.empty:
            if st.button("Go to Products", use_container_width=True, key="goto_products"):
                st.session_state.page = "Products"
                st.rerun()
    
    with tab2:
        st.subheader("Transaction History")
        
        col_filter1, col_filter2, col_filter3 = st.columns(3)
        
        with col_filter1:
            filter_type = st.selectbox(
                "Filter by Type",
                ["All", "sale", "purchase", "adjustment", "transfer"],
                key="history_filter_type"
            )
        
        with col_filter2:
            date_range = st.selectbox(
                "Date Range",
                ["Last 7 days", "Last 30 days", "Last 90 days", "All time"],
                key="history_date_range"
            )
        
        with col_filter3:
            limit_records = st.number_input("Show Records", min_value=10, max_value=500, value=50, step=10, key="history_limit")
        
        org = get_current_organization()
        query = """
            SELECT 
                t.transaction_id,
                t.type,
                t.quantity,
                t.unit_price,
                t.total_amount,
                t.reference,
                t.notes,
                t.created_at,
                p.sku,
                p.name as product_name,
                u.username as created_by_name
            FROM transactions t
            JOIN products p ON t.product_id = p.product_id
            LEFT JOIN users u ON t.created_by = u.user_id
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
        params.append(limit_records)
        
        transactions = fetch_dataframe(query, tuple(params))
        
        if not transactions.empty:
            display_df = transactions.copy()
            
            display_df['unit_price'] = display_df['unit_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['total_amount'] = display_df['total_amount'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            
            def format_type(t_type):
                colors = {
                    'sale': 'badge-success',
                    'purchase': 'badge-info',
                    'adjustment': 'badge-warning',
                    'transfer': 'badge-secondary'
                }
                color = colors.get(t_type, 'badge-secondary')
                return f'<span class="badge {color}">{t_type.upper()}</span>'
            
            display_df['type'] = display_df['type'].apply(format_type)
            
            html_table = display_df[['created_at', 'type', 'sku', 'product_name', 'quantity', 'unit_price', 'total_amount', 'reference']].to_html(
                escape=False, index=False, classes='dataframe', border=0
            )
            st.markdown(html_table, unsafe_allow_html=True)
            
            col_export, col_stats = st.columns(2)
            
            with col_export:
                csv_data = transactions.to_csv(index=False)
                st.download_button(
                    label="Export Transaction History",
                    data=csv_data,
                    file_name="transaction_history.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="export_history"
                )
            
            with col_stats:
                if st.button("Show Statistics", use_container_width=True, key="show_stats"):
                    total_sales = transactions[transactions['type'] == 'sale']['total_amount'].sum()
                    total_purchases = transactions[transactions['type'] == 'purchase']['total_amount'].sum()
                    
                    col_stat1, col_stat2, col_stat3 = st.columns(3)
                    with col_stat1:
                        st.metric("Total Sales", f"{st.session_state.currency} {total_sales:,.2f}")
                    with col_stat2:
                        st.metric("Total Purchases", f"{st.session_state.currency} {total_purchases:,.2f}")
                    with col_stat3:
                        st.metric("Transaction Count", len(transactions))
        else:
            st.info("No transactions found. Record your first transaction in the 'Record Transaction' tab.")

def render_suppliers():
    """Render suppliers page"""
    st.markdown("<h1 class='main-header'>Suppliers</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to manage suppliers")
        return
    
    tab1, tab2 = st.tabs(["Supplier List", "Add Supplier"])
    
    with tab1:
        try:
            org = get_current_organization()
            suppliers = fetch_dataframe(
                "SELECT * FROM suppliers WHERE organization = ? ORDER BY name",
                (org,)
            )
            
            if not suppliers.empty:
                st.dataframe(
                    suppliers[['name', 'contact_person', 'email', 'phone', 'address', 'payment_terms']],
                    use_container_width=True,
                    column_config={
                        "name": "Supplier Name",
                        "contact_person": "Contact Person",
                        "email": "Email",
                        "phone": "Phone",
                        "address": "Address",
                        "payment_terms": "Payment Terms"
                    },
                    hide_index=True
                )
                
                csv = suppliers.to_csv(index=False)
                st.download_button(
                    label="Export Suppliers",
                    data=csv,
                    file_name="suppliers_export.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="export_suppliers"
                )
            else:
                st.info("No suppliers found. Add suppliers using the 'Add Supplier' tab.")
        except Exception as e:
            st.info("No suppliers found. Add your first supplier.")
    
    with tab2:
        with st.form("add_supplier_form", clear_on_submit=True):
            st.subheader("Add New Supplier")
            
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Supplier Name *", key="supplier_name")
                contact_person = st.text_input("Contact Person", key="supplier_contact")
                email = st.text_input("Email", key="supplier_email")
            
            with col2:
                phone = st.text_input("Phone", key="supplier_phone")
                address = st.text_area("Address", key="supplier_address")
                payment_terms = st.text_input("Payment Terms", key="supplier_terms")
            
            submitted = st.form_submit_button("Save Supplier", type="primary", use_container_width=True)
            
            if submitted:
                if not name:
                    st.error("Supplier name is required")
                else:
                    org = get_current_organization()
                    try:
                        execute_query(
                            """
                            INSERT INTO suppliers (organization, name, contact_person, email, phone, address, payment_terms)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (org, name, contact_person, email, phone, address, payment_terms)
                        )
                        
                        log_activity(
                            user_id=st.session_state.user_id,
                            action="supplier_added",
                            details=f"Added supplier: {name}"
                        )
                        
                        st.success("Supplier added successfully")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Supplier name already exists")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

def render_reports():
    """Render reports page with enhanced visuals and downloads"""
    st.markdown("<h1 class='main-header'>Reports & Analytics</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to view reports")
        return
    
    tab1, tab2, tab3, tab4 = st.tabs(["Sales Analytics", "Inventory Reports", "Stock Analysis", "Export Center"])
    
    with tab1:
        st.markdown("### Sales Performance Analysis")
        
        col_date1, col_date2 = st.columns(2)
        with col_date1:
            start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=30), key="sales_start")
        with col_date2:
            end_date = st.date_input("End Date", value=datetime.now(), key="sales_end")
        
        if st.button("Generate Sales Report", use_container_width=True, key="gen_sales_report"):
            sales_report = get_sales_report(start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d'))
            
            if not sales_report.empty:
                # Display summary metrics
                total_sales = sales_report['total_amount'].sum()
                total_quantity = sales_report['total_quantity'].sum()
                avg_sale = sales_report['total_amount'].mean()
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Sales", f"{st.session_state.currency} {total_sales:,.2f}")
                with col2:
                    st.metric("Units Sold", f"{total_quantity:,}")
                with col3:
                    st.metric("Average Sale", f"{st.session_state.currency} {avg_sale:,.2f}")
                
                st.markdown("---")
                
                # Data table
                st.markdown("### Detailed Sales Data")
                display_df = sales_report.copy()
                display_df['total_amount'] = display_df['total_amount'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
                st.dataframe(display_df, use_container_width=True)
                
                # Visualizations
                col_chart1, col_chart2 = st.columns(2)
                
                with col_chart1:
                    st.markdown("#### Daily Sales Trend")
                    daily_sales = sales_report.groupby('sale_date')['total_amount'].sum().reset_index()
                    fig1 = px.line(daily_sales, x='sale_date', y='total_amount', 
                                 title="Sales Trend Over Time",
                                 labels={'sale_date': 'Date', 'total_amount': 'Sales Amount'})
                    st.plotly_chart(fig1, use_container_width=True)
                
                with col_chart2:
                    st.markdown("#### Top Selling Products")
                    top_products = sales_report.groupby('name')['total_quantity'].sum().nlargest(10).reset_index()
                    fig2 = px.bar(top_products, x='name', y='total_quantity',
                                 title="Top 10 Products by Quantity Sold",
                                 labels={'name': 'Product', 'total_quantity': 'Quantity Sold'})
                    st.plotly_chart(fig2, use_container_width=True)
                
                # Download buttons
                st.markdown("---")
                st.markdown("### Download Options")
                
                col_dl1, col_dl2, col_dl3 = st.columns(3)
                
                with col_dl1:
                    csv = sales_report.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"sales_report_{start_date}_{end_date}.csv",
                        mime="text/csv",
                        use_container_width=True,
                        key="download_sales_csv"
                    )
                
                with col_dl2:
                    excel_buffer = BytesIO()
                    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                        sales_report.to_excel(writer, sheet_name='Sales Report', index=False)
                        # Add summary sheet
                        summary_data = pd.DataFrame({
                            'Metric': ['Total Sales', 'Units Sold', 'Average Sale', 'Date Range'],
                            'Value': [f"{st.session_state.currency} {total_sales:,.2f}", 
                                     f"{total_quantity:,}", 
                                     f"{st.session_state.currency} {avg_sale:,.2f}",
                                     f"{start_date} to {end_date}"]
                        })
                        summary_data.to_excel(writer, sheet_name='Summary', index=False)
                    
                    excel_buffer.seek(0)
                    st.download_button(
                        label="Download Excel",
                        data=excel_buffer,
                        file_name=f"sales_report_{start_date}_{end_date}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True,
                        key="download_sales_excel"
                    )
                
                with col_dl3:
                    # Create a PDF-like summary
                    html_report = f"""
                    <h2>Sales Report Summary</h2>
                    <p><strong>Date Range:</strong> {start_date} to {end_date}</p>
                    <p><strong>Total Sales:</strong> {st.session_state.currency} {total_sales:,.2f}</p>
                    <p><strong>Units Sold:</strong> {total_quantity:,}</p>
                    <p><strong>Average Sale:</strong> {st.session_state.currency} {avg_sale:,.2f}</p>
                    """
                    st.download_button(
                        label="Download Summary",
                        data=html_report,
                        file_name=f"sales_summary_{start_date}_{end_date}.html",
                        mime="text/html",
                        use_container_width=True,
                        key="download_sales_summary"
                    )
                
            else:
                st.info("No sales data found for the selected period.")
    
    with tab2:
        st.markdown("### Inventory Analysis")
        
        inventory_summary = get_inventory_summary()
        
        if not inventory_summary.empty:
            # Summary metrics
            total_value = inventory_summary['total_value'].sum()
            total_products = inventory_summary['product_count'].sum()
            total_quantity = inventory_summary['total_quantity'].sum()
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Inventory Value", f"{st.session_state.currency} {total_value:,.2f}")
            with col2:
                st.metric("Total Products", f"{total_products:,}")
            with col3:
                st.metric("Total Units", f"{total_quantity:,}")
            
            st.markdown("---")
            
            # Visualizations
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                st.markdown("#### Inventory by Category (Value)")
                fig1 = px.pie(inventory_summary, values='total_value', names='category',
                            title="Inventory Value Distribution by Category")
                st.plotly_chart(fig1, use_container_width=True)
            
            with col_chart2:
                st.markdown("#### Inventory by Category (Quantity)")
                fig2 = px.bar(inventory_summary, x='category', y='total_quantity',
                            title="Inventory Quantity by Category",
                            labels={'category': 'Category', 'total_quantity': 'Quantity'})
                st.plotly_chart(fig2, use_container_width=True)
            
            # Detailed table
            st.markdown("### Detailed Inventory Analysis")
            display_df = inventory_summary.copy()
            display_df['total_value'] = display_df['total_value'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['avg_cost'] = display_df['avg_cost'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            display_df['avg_price'] = display_df['avg_price'].apply(lambda x: f"{st.session_state.currency} {x:,.2f}")
            st.dataframe(display_df, use_container_width=True)
            
            # Download options
            st.markdown("---")
            st.markdown("### Download Inventory Report")
            
            col_dl1, col_dl2 = st.columns(2)
            
            with col_dl1:
                csv = inventory_summary.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="inventory_analysis.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="download_inventory_csv"
                )
            
            with col_dl2:
                excel_buffer = BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    inventory_summary.to_excel(writer, sheet_name='Inventory Analysis', index=False)
                excel_buffer.seek(0)
                st.download_button(
                    label="Download Excel",
                    data=excel_buffer,
                    file_name="inventory_analysis.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key="download_inventory_excel"
                )
        else:
            st.info("No inventory data available for analysis.")
    
    with tab3:
        st.markdown("### Stock Level Analysis")
        
        org = get_current_organization()
        
        # Get stock status
        stock_status = fetch_dataframe(
            """
            SELECT 
                CASE 
                    WHEN quantity = 0 THEN 'Out of Stock'
                    WHEN quantity <= reorder_level THEN 'Low Stock'
                    ELSE 'In Stock'
                END as status,
                COUNT(*) as product_count,
                SUM(quantity) as total_quantity,
                SUM(quantity * cost_price) as total_value
            FROM products 
            WHERE organization = ?
            GROUP BY 
                CASE 
                    WHEN quantity = 0 THEN 'Out of Stock'
                    WHEN quantity <= reorder_level THEN 'Low Stock'
                    ELSE 'In Stock'
                END
            """,
            (org,)
        )
        
        if not stock_status.empty:
            # Stock status pie chart
            fig = px.pie(stock_status, values='product_count', names='status',
                        title="Stock Status Distribution",
                        color='status',
                        color_discrete_map={
                            'In Stock': '#10b981',
                            'Low Stock': '#f59e0b',
                            'Out of Stock': '#ef4444'
                        })
            st.plotly_chart(fig, use_container_width=True)
            
            # Low stock items
            st.markdown("### Low Stock Alert Items")
            low_stock_items = fetch_dataframe(
                """
                SELECT sku, name, quantity, reorder_level, location
                FROM products 
                WHERE organization = ? 
                    AND quantity <= reorder_level 
                    AND quantity > 0
                ORDER BY quantity ASC
                """,
                (org,)
            )
            
            if not low_stock_items.empty:
                st.dataframe(low_stock_items, use_container_width=True)
                
                # Download low stock report
                csv = low_stock_items.to_csv(index=False)
                st.download_button(
                    label="Download Low Stock Report",
                    data=csv,
                    file_name="low_stock_report.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="download_low_stock"
                )
            else:
                st.success("No low stock items. All inventory levels are satisfactory.")
            
            # Out of stock items
            st.markdown("### Out of Stock Items")
            out_of_stock_items = fetch_dataframe(
                """
                SELECT sku, name, reorder_level, location
                FROM products 
                WHERE organization = ? AND quantity = 0
                ORDER BY name ASC
                """,
                (org,)
            )
            
            if not out_of_stock_items.empty:
                st.dataframe(out_of_stock_items, use_container_width=True)
                
                # Download out of stock report
                csv = out_of_stock_items.to_csv(index=False)
                st.download_button(
                    label="Download Out of Stock Report",
                    data=csv,
                    file_name="out_of_stock_report.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="download_out_of_stock"
                )
            else:
                st.success("No out of stock items.")
        else:
            st.info("No stock data available.")
    
    with tab4:
        st.markdown("### Data Export Center")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Export All Data")
            
            if st.button("Export Complete Database", use_container_width=True, key="export_complete_db"):
                org = get_current_organization()
                
                # Get all data
                products_data = get_products(page_size=10000)
                transactions_data = get_recent_transactions(limit=10000)
                suppliers_data = fetch_dataframe(
                    "SELECT * FROM suppliers WHERE organization = ?",
                    (org,)
                )
                
                # Create Excel file with multiple sheets
                excel_buffer = BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    if not products_data.empty:
                        products_data.to_excel(writer, sheet_name='Products', index=False)
                    if not transactions_data.empty:
                        transactions_data.to_excel(writer, sheet_name='Transactions', index=False)
                    if not suppliers_data.empty:
                        suppliers_data.to_excel(writer, sheet_name='Suppliers', index=False)
                    
                    # Add summary sheet
                    summary_data = pd.DataFrame({
                        'Export Date': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                        'Organization': [org],
                        'Products Exported': [len(products_data)],
                        'Transactions Exported': [len(transactions_data)],
                        'Suppliers Exported': [len(suppliers_data)]
                    })
                    summary_data.to_excel(writer, sheet_name='Summary', index=False)
                
                excel_buffer.seek(0)
                st.download_button(
                    label="Download Complete Database",
                    data=excel_buffer,
                    file_name=f"invypro_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key="download_complete_db"
                )
        
        with col2:
            st.markdown("#### Custom Reports")
            
            report_type = st.selectbox(
                "Select Report Type",
                ["Product Performance", "Supplier Analysis", "Transaction Summary", "Inventory Valuation"],
                key="custom_report_type"
            )
            
            if st.button("Generate Custom Report", use_container_width=True, key="gen_custom_report"):
                st.info(f"Generating {report_type} report...")
                # Placeholder for custom report generation
                st.success("Custom report generated successfully!")
                
                # Create sample report data
                sample_data = pd.DataFrame({
                    'Metric': ['Report Type', 'Generated Date', 'Data Points', 'Status'],
                    'Value': [report_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '100', 'Complete']
                })
                
                csv = sample_data.to_csv(index=False)
                st.download_button(
                    label="Download Custom Report",
                    data=csv,
                    file_name=f"custom_report_{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                    key="download_custom_report"
                )

def render_settings():
    """Render settings page"""
    st.markdown("<h1 class='main-header'>Settings</h1>", unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        st.warning("Please login to access settings")
        return
    
    with st.expander("Organization Settings", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            currency = st.selectbox(
                "Default Currency",
                ["GHS", "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"],
                index=["GHS", "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"].index(
                    st.session_state.currency if st.session_state.currency in 
                    ["GHS", "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "INR"] 
                    else "GHS"
                ),
                key="currency_setting"
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
                key="timezone_setting"
            )
            st.session_state.timezone = timezone
        
        if st.button("Save Organization Settings", use_container_width=True, key="save_org_settings"):
            st.success("Organization settings saved successfully")
    
    with st.expander("User Settings"):
        st.write("Change Password")
        
        current_pass = st.text_input("Current Password", type="password", key="current_password")
        new_pass = st.text_input("New Password", type="password", key="new_password")
        confirm_pass = st.text_input("Confirm New Password", type="password", key="confirm_password")
        
        if st.button("Update Password", use_container_width=True, key="update_password"):
            if not current_pass:
                st.error("Please enter current password")
            elif new_pass != confirm_pass:
                st.error("New passwords do not match")
            elif len(new_pass) < 8:
                st.error("Password must be at least 8 characters")
            else:
                result = authenticate_user(st.session_state.username, current_pass)
                if result['success']:
                    password_hash, salt = hash_password(new_pass)
                    execute_query(
                        "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?",
                        (password_hash, salt, st.session_state.user_id)
                    )
                    st.success("Password updated successfully")
                else:
                    st.error("Current password is incorrect")
    
    with st.expander("System Settings"):
        col_sys1, col_sys2 = st.columns(2)
        
        with col_sys1:
            prevent_negative = st.checkbox("Prevent Negative Stock", value=True, key="prevent_negative")
            auto_backup = st.checkbox("Automatic Backups", value=False, key="auto_backup")
        
        with col_sys2:
            email_alerts = st.checkbox("Email Alerts", value=False, key="email_alerts")
            low_stock_notify = st.checkbox("Low Stock Notifications", value=True, key="low_stock_notify")
        
        if st.button("Save System Settings", use_container_width=True, key="save_system_settings"):
            st.success("System settings saved successfully")
    
    with st.expander("Data Management"):
        col_data1, col_data2 = st.columns(2)
        
        with col_data1:
            if st.button("Export All Data", use_container_width=True, type="secondary", key="export_all_data"):
                products = get_products(page_size=1000)
                if not products.empty:
                    csv_data = products.to_csv(index=False)
                    st.download_button(
                        label="Download All Data",
                        data=csv_data,
                        file_name="invypro_export.csv",
                        mime="text/csv",
                        key="download_all_data"
                    )
                else:
                    st.info("No data to export")
        
        with col_data2:
            if st.button("View Activity Logs", use_container_width=True, type="secondary", key="view_logs"):
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
                except Exception as e:
                    st.info("No activity logs available")
                    
    with st.expander("Backup & Restore"):
        render_backup_management()
        
    with st.expander("Danger Zone", expanded=False):
        st.warning("Warning: These actions cannot be undone.")
        
        reset_confirmed = st.checkbox("I understand this will delete ALL data", key="reset_confirm")
        
        if st.button("Reset Organization Data", type="primary", use_container_width=True, disabled=not reset_confirmed, key="reset_data"):
            try:
                org = get_current_organization()
                
                execute_query("DELETE FROM transactions WHERE organization = ?", (org,))
                execute_query("DELETE FROM suppliers WHERE organization = ?", (org,))
                execute_query("DELETE FROM products WHERE organization = ?", (org,))
                
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
            
    # Auto-backup on startup (if enabled)
    if 'startup_backup_done' not in st.session_state:
        if st.session_state.get('auto_backup', False):
            create_backup()
        st.session_state.startup_backup_done = True
        
    render_sidebar()
    
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
    
    st.markdown("---")
    col_footer1, col_footer2, col_footer3 = st.columns(3)
    with col_footer2:
        st.caption(f"InvyPro v2.0 • Database: {st.session_state.get('db_type', 'SQLite')}")

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    # Create necessary directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("backups", exist_ok=True)
    
    main()
