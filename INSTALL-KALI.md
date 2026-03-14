# DFlagger Installation Guide for Kali Linux

## 🚀 Quick Start (Recommended)

### Method 1: Using the Setup Script

```bash
cd ~/DFlagger
./setup.sh
```

### Method 2: Manual Docker Compose (If setup.sh fails)

```bash
cd ~/DFlagger

# Use docker compose (v2) or docker-compose (v1)
docker-compose -f docker-compose.simple.yml up --build -d

# OR
docker compose -f docker-compose.simple.yml up --build -d
```

## 🔍 Accessing the Application

After installation:

| Service | URL | Description |
|---------|-----|-------------|
| **Frontend** | http://localhost:3000 | Main web interface |
| **Backend API** | http://localhost:4000 | API endpoint |
| **Health Check** | http://localhost:4000/api/health | Backend status |
| **Database** | localhost:5432 | PostgreSQL (if needed) |

## 📊 Managing the Application

### Check Status
```bash
docker ps
```

### View Logs
```bash
# All services
docker-compose -f docker-compose.simple.yml logs -f

# Backend only
docker-compose -f docker-compose.simple.yml logs -f backend

# Frontend only
docker-compose -f docker-compose.simple.yml logs -f frontend

# Database only
docker-compose -f docker-compose.simple.yml logs -f postgres
```

### Stop the Application
```bash
docker-compose -f docker-compose.simple.yml down
```

### Restart
```bash
docker-compose -f docker-compose.simple.yml restart
```

### Full Reset (removes data!)
```bash
docker-compose -f docker-compose.simple.yml down -v
docker-compose -f docker-compose.simple.yml up --build -d
```

## 🐛 Troubleshooting

### Issue: "docker-compose: command not found"

**Solution 1:** Use docker compose (space, no hyphen)
```bash
docker compose -f docker-compose.simple.yml up --build -d
```

**Solution 2:** Install docker-compose
```bash
sudo apt update
sudo apt install docker-compose-plugin
# OR
sudo apt install docker-compose
```

### Issue: Frontend build fails with TypeScript errors

```bash
# Clean and rebuild
docker-compose -f docker-compose.simple.yml down
docker-compose -f docker-compose.simple.yml build --no-cache frontend
docker-compose -f docker-compose.simple.yml up -d
```

### Issue: Database connection failed

```bash
# Check if postgres is running
docker ps | grep postgres

# Check postgres logs
docker-compose -f docker-compose.simple.yml logs postgres

# Wait a bit longer and restart backend
docker-compose -f docker-compose.simple.yml restart backend
```

### Issue: Port already in use

```bash
# Check what's using port 3000 (frontend)
sudo lsof -i :3000

# Check what's using port 4000 (backend)
sudo lsof -i :4000

# Kill the process or change ports in docker-compose.simple.yml
```

### Issue: Permission denied

```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
# Log out and log back in, then try again
```

## 📝 Database Migrations

If migrations don't run automatically:

```bash
# Run migrations manually
docker-compose -f docker-compose.simple.yml exec backend npx prisma migrate deploy

# Or enter the backend container
docker-compose -f docker-compose.simple.yml exec backend sh
# Then inside container:
npx prisma migrate deploy
```

## 🔄 Updating the Application

```bash
cd ~/DFlagger
git pull origin main  # or update files manually
docker-compose -f docker-compose.simple.yml down
docker-compose -f docker-compose.simple.yml up --build -d
```

## 🌐 Network Configuration

If you want to access from another machine on your network:

1. Find your Kali IP:
```bash
ip addr show | grep "inet " | head -1
```

2. Access using the IP instead of localhost:
```
http://<your-kali-ip>:3000
http://<your-kali-ip>:4000
```

## 💾 Backup Database

```bash
# Create backup
docker-compose -f docker-compose.simple.yml exec postgres pg_dump -U postgres dflagger > backup.sql

# Restore backup
cat backup.sql | docker-compose -f docker-compose.simple.yml exec -T postgres psql -U postgres dflagger
```

## ❌ Uninstall

```bash
cd ~/DFlagger

# Stop and remove containers
docker-compose -f docker-compose.simple.yml down -v

# Remove images (optional)
docker rmi dflagger-backend dflagger-frontend

# Remove all data (optional)
docker volume rm dflagger_postgres_data
```

## 📞 Getting Help

If you encounter issues:

1. Check logs: `docker-compose -f docker-compose.simple.yml logs`
2. Check Docker status: `docker ps`
3. Restart services: `docker-compose -f docker-compose.simple.yml restart`
4. Full reset: `docker-compose -f docker-compose.simple.yml down -v && docker-compose -f docker-compose.simple.yml up --build -d`
