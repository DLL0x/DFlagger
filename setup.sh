#!/bin/bash

# DFlagger Setup Script
set -e

echo "🚀 DFlagger Setup Script"
echo "========================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check for Docker Compose (v2 or v1)
DOCKER_COMPOSE=""
if docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
    echo "✅ Docker Compose v2 found"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
    echo "✅ Docker Compose v1 found"
else
    echo "❌ Docker Compose not found. Please install Docker Compose:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker found"
echo ""

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    # Generate random passwords
    DB_PASS=$(openssl rand -base64 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    JWT_SEC=$(openssl rand -base64 32 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    cat > .env << EOF
DB_PASSWORD=${DB_PASS}
JWT_SECRET=${JWT_SEC}
EOF
    echo "✅ .env file created with random secrets"
else
    echo "✅ .env file already exists"
fi

echo ""
echo "🔧 Building and starting services..."
echo "   Using: $DOCKER_COMPOSE"
echo ""

# Stop any existing containers
$DOCKER_COMPOSE -f docker-compose.prod.yml down 2>/dev/null || true

# Build and start services
$DOCKER_COMPOSE -f docker-compose.prod.yml up --build -d

echo ""
echo "⏳ Waiting for database to be ready..."
sleep 15

echo ""
echo "🗄️  Running database migrations..."
# Try to run migrations, but don't fail if backend isn't ready yet
$DOCKER_COMPOSE -f docker-compose.prod.yml exec -T backend npx prisma migrate deploy 2>/dev/null || echo "⚠️  Migration will run automatically when backend starts"

echo ""
echo "✅ DFlagger setup complete!"
echo ""
echo "📱 Access the application:"
echo "   Frontend: http://localhost"
echo "   Backend API: http://localhost:4000"
echo "   Health Check: http://localhost:4000/api/health"
echo ""
echo "📊 Useful commands:"
echo "   View logs:    $DOCKER_COMPOSE -f docker-compose.prod.yml logs -f"
echo "   Stop:         $DOCKER_COMPOSE -f docker-compose.prod.yml down"
echo "   Restart:      $DOCKER_COMPOSE -f docker-compose.prod.yml restart"
echo ""

# Check if services are running
echo "🔍 Checking service status..."
$DOCKER_COMPOSE -f docker-compose.prod.yml ps
