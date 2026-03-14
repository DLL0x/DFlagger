#!/bin/bash

set -e

echo "🚀 DFlagger Setup"
echo "================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not installed"
    echo "   Install: https://docs.docker.com/get-docker/"
    exit 1
fi

# Detect docker compose
if docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "❌ Docker Compose not installed"
    exit 1
fi

echo "✅ Docker found"
echo ""

# Stop and remove old containers
echo "🧹 Cleaning up..."
$DOCKER_COMPOSE down -v 2>/dev/null || true

# Build and start
echo "🔨 Building DFlagger..."
$DOCKER_COMPOSE up --build -d

# Wait for services
echo "⏳ Starting services..."
sleep 10

echo ""
echo "✅ DFlagger is running!"
echo ""
echo "📱 Access:"
echo "   Frontend: http://localhost:3000"
echo "   Backend:  http://localhost:4000"
echo "   Health:   http://localhost:4000/api/health"
echo ""
echo "📊 Commands:"
echo "   Logs:     $DOCKER_COMPOSE logs -f"
echo "   Stop:     $DOCKER_COMPOSE down"
echo "   Restart:  $DOCKER_COMPOSE restart"
echo ""

# Show status
$DOCKER_COMPOSE ps
