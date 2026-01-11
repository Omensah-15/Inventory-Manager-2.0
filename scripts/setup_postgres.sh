#!/bin/bash

echo "Setting up InvyPro with Docker..."

# Create directories
mkdir -p data backups logs

# Start services
docker-compose up -d

echo "Waiting for services to start..."
sleep 10

echo "InvyPro is now available at: http://localhost:8501"
echo ""
echo "Default credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "To stop: docker-compose down"
echo "To view logs: docker-compose logs -f"
