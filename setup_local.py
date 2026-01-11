#!/usr/bin/env python3
"""
Local setup script for InvyPro without Docker
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f" {text}")
    print("="*60)

def check_python():
    """Check Python version"""
    print_header("Checking Python")
    
    if sys.version_info < (3, 8):
        print(f"Error: Python 3.8+ required. Current: {sys.version}")
        return False
    
    print(f"OK: Python {sys.version}")
    return True

def create_directories():
    """Create necessary directories"""
    print_header("Creating Directories")
    
    directories = ['data', 'backups', 'logs']
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        dir_path.mkdir(exist_ok=True)
        print(f"Created {dir_name}/ directory")
    
    return True

def install_dependencies():
    """Install Python dependencies"""
    print_header("Installing Dependencies")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("Error: requirements.txt not found")
        return False
    
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            check=True,
            capture_output=True,
            text=True
        )
        print("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e.stderr}")
        return False

def setup_database():
    """Setup PostgreSQL database"""
    print_header("Database Setup Instructions")
    
    print("\nIMPORTANT: You need to setup PostgreSQL manually.")
    print("\nFollow these steps:")
    
    system = platform.system()
    if system == "Linux":
        print("\n1. Install PostgreSQL:")
        print("   Ubuntu/Debian: sudo apt install postgresql postgresql-contrib")
        print("   Fedora/RHEL: sudo dnf install postgresql-server postgresql-contrib")
        
        print("\n2. Start PostgreSQL:")
        print("   sudo systemctl start postgresql")
        print("   sudo systemctl enable postgresql")
        
    elif system == "Darwin":  # macOS
        print("\n1. Install PostgreSQL:")
        print("   Homebrew: brew install postgresql@15")
        
        print("\n2. Start PostgreSQL:")
        print("   brew services start postgresql@15")
        
    elif system == "Windows":
        print("\n1. Install PostgreSQL:")
        print("   Download from: https://www.postgresql.org/download/windows/")
    
    print("\n3. Create database and user:")
    print("   sudo -u postgres psql")
    print("   CREATE DATABASE invypro;")
    print("   CREATE USER invypro_user WITH PASSWORD 'invypro_pass';")
    print("   GRANT ALL PRIVILEGES ON DATABASE invypro TO invypro_user;")
    print("   \\q")
    
    print("\n4. Test connection:")
    print("   psql -h localhost -U invypro_user -d invypro")
    
    input("\nPress Enter after setting up the database...")
    return True

def main():
    """Main setup function"""
    print_header("InvyPro Local Setup")
    
    steps = [
        ("Checking Python", check_python),
        ("Creating directories", create_directories),
        ("Installing dependencies", install_dependencies),
        ("Database setup", setup_database),
    ]
    
    for step_name, step_func in steps:
        if not step_func():
            print(f"\nSetup failed at: {step_name}")
            print("Please fix the issue and run the setup again.")
            sys.exit(1)
    
    print_header("Setup Complete!")
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

if __name__ == "__main__":
    main()
