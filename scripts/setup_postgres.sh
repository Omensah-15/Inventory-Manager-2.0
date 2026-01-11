#!/bin/bash

# InvyPro PostgreSQL Setup Script

echo "Setting up InvyPro with PostgreSQL..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed."
    exit 1
fi

# Create necessary directories
mkdir -p data backups scripts

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Note: .env file created. Please edit it with your settings."
fi

# Start services
echo "Starting PostgreSQL and InvyPro..."
docker-compose up -d

echo "Waiting for services to start..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "Success: Services are running!"
    echo ""
    echo "InvyPro is now available at: http://localhost:8501"
    echo ""
    echo "Default credentials:"
    echo "   Username: admin"
    echo "   Password: admin123"
    echo ""
    echo "Data directory: ./data"
    echo "Backup directory: ./backups"
    echo ""
    echo "To stop the application: docker-compose down"
    echo "To view logs: docker-compose logs -f"
else
    echo "Error: Services failed to start. Check logs with: docker-compose logs"
    exit 1
fi
