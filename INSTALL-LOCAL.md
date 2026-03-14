# DFlagger Local Development Setup (Without Docker)

⚠️ **Note**: This is for development only. For production, use Docker.

## Prerequisites

1. **Node.js 20+** - [Download here](https://nodejs.org/)
2. **PostgreSQL 15+** - Install on Kali:
   ```bash
   sudo apt update
   sudo apt install postgresql postgresql-contrib
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   ```

## Setup Steps

### 1. Setup PostgreSQL Database

```bash
# Switch to postgres user
sudo -u postgres psql

# Inside psql, create database:
CREATE DATABASE dflagger;
CREATE USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE dflagger TO postgres;
\q
```

### 2. Backend Setup

```bash
cd ~/DFlagger/backend

# Copy environment file
cp .env.example .env

# Install dependencies
npm install

# Generate Prisma Client
npx prisma generate

# Run database migrations
npx prisma migrate dev

# Start development server
npm run dev
```

Backend will run at: http://localhost:4000

### 3. Frontend Setup

Open a NEW terminal window:

```bash
cd ~/DFlagger/frontend/app

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend will run at: http://localhost:5173

## Access URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:4000 |
| Prisma Studio | http://localhost:5555 |

## Troubleshooting

### "Can't reach database server at localhost:5432"

PostgreSQL is not running:
```bash
sudo systemctl start postgresql
sudo systemctl status postgresql
```

### "Database dflagger does not exist"

Create the database:
```bash
sudo -u postgres createdb dflagger
```

### Prisma Client errors

Regenerate Prisma Client:
```bash
cd ~/DFlagger/backend
npx prisma generate
npx prisma migrate dev
```

### Port already in use

Kill processes using ports:
```bash
sudo lsof -ti:4000 | xargs kill -9
sudo lsof -ti:5173 | xargs kill -9
```

## Recommended: Use Docker Instead

Local setup is complex. Use Docker for easier setup:

```bash
cd ~/DFlagger
docker-compose -f docker-compose.simple.yml up --build -d
```

Then access:
- Frontend: http://localhost:3000
- Backend: http://localhost:4000
