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
    
    with open(
