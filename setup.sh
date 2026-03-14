#!/bin/bash

# DFlagger Setup Script

echo "🚀 DFlagger Setup Script"
echo "========================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose found"
echo ""

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
DB_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)
EOF
    echo "✅ .env file created with random secrets"
else
    echo "✅ .env file already exists"
fi

echo ""
echo "🔧 Building and starting services..."
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up --build -d

echo ""
echo "⏳ Waiting for database to be ready..."
sleep 10

echo ""
echo "🗄️  Running database migrations..."
docker-compose -f docker-compose.prod.yml exec -T backend npx prisma migrate deploy

echo ""
echo "✅ DFlagger is now running!"
echo ""
echo "📱 Access the application:"
echo "   Frontend: http://localhost"
echo "   Backend API: http://localhost:4000"
echo "   Health Check: http://localhost:4000/api/health"
echo ""
echo "📊 View logs:"
echo "   docker-compose -f docker-compose.prod.yml logs -f"
echo ""
echo "🛑 To stop:"
echo "   docker-compose -f docker-compose.prod.yml down"
