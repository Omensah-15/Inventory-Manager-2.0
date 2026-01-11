"""
Configuration module for InvyPro Inventory Management System
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Base configuration"""
    # Application
    APP_NAME = "InvyPro Inventory Manager"
    APP_VERSION = "2.0.0"
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '5432')
    DB_NAME = os.getenv('DB_NAME', 'invypro')
    DB_USER = os.getenv('DB_USER', 'invypro_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'invypro_pass')
    DB_SSLMODE = os.getenv('DB_SSLMODE', 'disable')
    
    # Security
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', '3600'))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
    LOCKOUT_MINUTES = int(os.getenv('LOCKOUT_MINUTES', '15'))
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    
    # Paths
    DATA_DIR = BASE_DIR / 'data'
    BACKUP_DIR = BASE_DIR / 'backups'
    LOG_DIR = BASE_DIR / 'logs'
    TEMPLATE_DIR = BASE_DIR / 'templates'
    
    # Application settings
    DEFAULT_CURRENCY = os.getenv('DEFAULT_CURRENCY', 'USD')
    DEFAULT_TIMEZONE = os.getenv('DEFAULT_TIMEZONE', 'UTC')
    ITEMS_PER_PAGE = int(os.getenv('ITEMS_PER_PAGE', '50'))
    
    # Backup settings
    AUTO_BACKUP = os.getenv('AUTO_BACKUP', 'True').lower() == 'true'
    BACKUP_RETENTION_DAYS = int(os.getenv('BACKUP_RETENTION_DAYS', '30'))
    
    # Email notifications (if implemented)
    EMAIL_ENABLED = os.getenv('EMAIL_ENABLED', 'False').lower() == 'true'
    EMAIL_HOST = os.getenv('EMAIL_HOST', '')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
    EMAIL_USER = os.getenv('EMAIL_USER', '')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    
    @classmethod
    def get_database_url(cls):
        """Get database connection URL"""
        return f"postgresql://{cls.DB_USER}:{cls.DB_PASSWORD}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
    
    @classmethod
    def ensure_directories(cls):
        """Ensure all required directories exist"""
        directories = [cls.DATA_DIR, cls.BACKUP_DIR, cls.LOG_DIR]
        for directory in directories:
            directory.mkdir(exist_ok=True, parents=True)
    
    @classmethod
    def validate_config(cls):
        """Validate configuration"""
        errors = []
        
        # Check database configuration
        if not all([cls.DB_HOST, cls.DB_NAME, cls.DB_USER]):
            errors.append("Database configuration incomplete")
        
        # Check directories
        try:
            cls.ensure_directories()
        except Exception as e:
            errors.append(f"Failed to create directories: {str(e)}")
        
        return errors

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Override for production
    SECRET_KEY = os.getenv('SECRET_KEY')
    DB_SSLMODE = 'require'
    
    @classmethod
    def validate_config(cls):
        errors = super().validate_config()
        
        # Additional production checks
        if cls.SECRET_KEY == 'dev-secret-key-change-in-production':
            errors.append("SECRET_KEY must be set in production")
        
        if cls.DB_PASSWORD == 'invypro_pass':
            errors.append("Database password must be changed in production")
        
        return errors

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    DB_NAME = 'invypro_test'

# Configuration selection
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}

# Default to development if not specified
environment = os.getenv('APP_ENV', 'development').lower()
config = config_map.get(environment, DevelopmentConfig)

# Initialize directories
config.ensure_directories()
