#!/usr/bin/env python3
"""
Local setup script for InvyPro without Docker
"""

import os
import sys
import subprocess
import time
import platform
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f" {text}")
    print("="*60)

def run_command(cmd, description):
    """Run a shell command"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Success")
            return True
        else:
            print(f"✗ Failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False

def check_python():
    """Check Python version"""
    print_header("Checking Python")
    
    if sys.version_info < (3, 8):
        print(f"✗ Python 3.8+ required. Current: {sys.version}")
        return False
    
    print(f"✓ Python {sys.version}")
    return True

def check_postgres():
    """Check PostgreSQL installation"""
    print_header("Checking PostgreSQL")
    
    # Try different commands based on OS
    commands = [
        "psql --version",
        "pg_ctl --version",
        "postgres --version"
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✓ PostgreSQL found: {result.stdout.split()[2]}")
                return True
        except:
            continue
    
    print("✗ PostgreSQL not found")
    
    # Installation instructions
    system = platform.system()
    if system == "Linux":
        print("\nInstall PostgreSQL:")
        print("  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib")
        print("  Fedora/RHEL: sudo dnf install postgresql-server postgresql-contrib")
    elif system == "Darwin":  # macOS
        print("\nInstall PostgreSQL:")
        print("  Homebrew: brew install postgresql@15")
    elif system == "Windows":
        print("\nInstall PostgreSQL:")
        print("  Download from: https://www.postgresql.org/download/windows/")
    
    return False

def install_dependencies():
    """Install Python dependencies"""
    print_header("Installing Dependencies")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("✗ requirements.txt not found")
        return False
    
    return run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing Python packages"
    )

def create_env_file():
    """Create .env file from template"""
    print_header("Configuring Environment")
    
    env_example = Path(".env.example")
    env_file = Path(".env")
    
    if not env_example.exists():
        print("✗ .env.example not found")
        return False
    
    if env_file.exists():
        overwrite = input(".env file exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Using existing .env file")
            return True
    
    # Copy template
    with open(env_example, 'r') as f:
        content = f.read()
    
    with open(env_file, 'w') as f:
        f.write(content)
    
    print("✓ Created .env file from template")
    print("\nPlease edit .env file with your database credentials")
    return True

def setup_database():
    """Setup PostgreSQL database"""
    print_header("Setting up Database")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    db_name = os.getenv('DB_NAME', 'invypro')
    db_user = os.getenv('DB_USER', 'invypro_user')
    db_password = os.getenv('DB_PASSWORD', 'invypro_pass')
    
    print(f"Database: {db_name}")
    print(f"User: {db_user}")
    
    # Database setup commands
    setup_commands = f"""
# 1. Start PostgreSQL service
sudo service postgresql start  # Linux
# or
brew services start postgresql  # macOS

# 2. Login to PostgreSQL as postgres user
sudo -u postgres psql

# 3. Run these SQL commands:
CREATE DATABASE {db_name};
CREATE USER {db_user} WITH PASSWORD '{db_password}';
GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};
\\c {db_name}
GRANT ALL ON SCHEMA public TO {db_user};

# 4. Exit
\\q
"""
    
    print("\nRun these commands in your terminal:")
    print(setup_commands)
    
    input("\nPress Enter after setting up the database...")
    return True

def initialize_database():
    """Initialize database schema"""
    print_header("Initializing Database")
    
    try:
        # Import and run database initialization
        sys.path.insert(0, str(Path.cwd()))
        from app import init_database, Database
        
        if Database.test_connection():
            init_database()
            print("✓ Database initialized successfully")
            return True
        else:
            print("✗ Cannot connect to database")
            return False
            
    except Exception as e:
        print(f"✗ Database initialization failed: {str(e)}")
        return False

def create_directories():
    """Create necessary directories"""
    print_header("Creating Directories")
    
    directories = ['data', 'backups', 'logs', 'scripts']
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        dir_path.mkdir(exist_ok=True)
        print(f"✓ Created {dir_name}/ directory")
    
    return True

def setup_complete():
    """Display setup completion message"""
    print_header("Setup Complete!")
    
    print("\n InvyPro is ready to use!")
    print("\nNext steps:")
    print("1. Start the application:")
    print("   streamlit run app.py")
    print("\n2. Access the application:")
    print("   http://localhost:8501")
    print("\n3. Default credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n4. Create your organization account")
    print("\n5. Start managing your inventory!")
    
    # Quick commands
    print("\n Useful commands:")
    print("   Start app: streamlit run app.py")
    print("   Backup DB: ./scripts/backup_db.sh")
    print("   Restore DB: ./scripts/restore_db.sh <backup_file>")
    
    return True

def main():
    """Main setup function"""
    print_header("InvyPro Local Setup")
    
    steps = [
        ("Checking Python", check_python),
        ("Checking PostgreSQL", check_postgres),
        ("Creating directories", create_directories),
        ("Installing dependencies", install_dependencies),
        ("Configuring environment", create_env_file),
        ("Setting up database", setup_database),
        ("Initializing database", initialize_database),
        ("Finalizing setup", setup_complete),
    ]
    
    for step_name, step_func in steps:
        if not step_func():
            print(f"\n Setup failed at: {step_name}")
            print("Please fix the issue and run the setup again.")
            sys.exit(1)
    
    print("\n Setup completed successfully!")

if __name__ == "__main__":
    main()
