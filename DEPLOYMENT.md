# DFlagger Deployment Guide

## 📋 Prerequisites

- GitHub account (connected to VSCode)
- Docker (optional, for local deployment)
- Cloud account (Render, Railway, Vercel, or VPS)

---

## 🚀 Quick Deployment Options

### Option 1: Deploy to Render.com (Easiest - Free Tier Available)

1. **Fork/Push this repo to GitHub**

2. **Create Render Account**
   - Go to [render.com](https://render.com)
   - Sign up with GitHub

3. **Create Blueprint Instance**
   - Click "New +" → "Blueprint"
   - Connect your GitHub repo
   - Render will read `render.yaml` and create:
     - PostgreSQL database
     - Backend API service
     - Frontend static site

4. **Environment Variables**
   Render will auto-generate secrets. Add any custom ones in the dashboard.

5. **Deploy**
   - Push to `main` branch triggers auto-deployment

---

### Option 2: Deploy to Railway.app

1. **Install Railway CLI**
   ```bash
   npm i -g @railway/cli
   ```

2. **Login and Create Project**
   ```bash
   railway login
   railway init
   ```

3. **Add PostgreSQL Database**
   ```bash
   railway add --database postgres
   ```

4. **Deploy**
   ```bash
   railway up
   ```

---

### Option 3: Deploy with Docker (VPS/Own Server)

1. **Install Docker & Docker Compose**
   ```bash
   curl -fsSL https://get.docker.com | sh
   ```

2. **Clone Repo on Server**
   ```bash
   git clone https://github.com/yourusername/DFlagger.git
   cd DFlagger
   ```

3. **Create Environment File**
   ```bash
   echo "DB_PASSWORD=your-secure-password" > .env
   echo "JWT_SECRET=your-jwt-secret" >> .env
   ```

4. **Run with Docker Compose**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

5. **Run Migrations**
   ```bash
   docker-compose -f docker-compose.prod.yml exec backend npx prisma migrate deploy
   ```

---

### Option 4: Separate Deployments (Frontend + Backend)

#### Backend Deployment (Render/Railway/Heroku)

1. **Create new Web Service**
   - Connect your GitHub repo
   - Root Directory: `backend`
   - Build Command: `npm install && npx prisma generate && npm run build`
   - Start Command: `npx prisma migrate deploy && npm start`

2. **Add PostgreSQL Database**
   - Create PostgreSQL addon/service
   - Copy connection string to `DATABASE_URL`

3. **Environment Variables**
   ```
   DATABASE_URL=postgresql://...
   JWT_SECRET=your-secret-key
   NODE_ENV=production
   PORT=4000
   ```

#### Frontend Deployment (Vercel/Netlify)

1. **Create New Project**
   - Connect GitHub repo
   - Framework: Vite
   - Build Directory: `frontend/app/dist`

2. **Environment Variables**
   ```
   VITE_API_URL=https://your-backend-url.com
   ```

3. **Build Settings**
   - Build Command: `npm run build`
   - Output Directory: `dist`

---

## 🔐 Required Secrets/Environment Variables

| Variable | Description | Where to Set |
|----------|-------------|--------------|
| `DATABASE_URL` | PostgreSQL connection string | Backend service |
| `JWT_SECRET` | Secret for JWT tokens | Backend service |
| `NODE_ENV` | Set to `production` | Backend service |
| `VITE_API_URL` | Backend URL for frontend | Frontend build |
| `DOCKER_USERNAME` | Docker Hub username | GitHub Secrets |
| `DOCKER_PASSWORD` | Docker Hub password/token | GitHub Secrets |

---

## 📁 GitHub Secrets Setup

Go to your GitHub repo → Settings → Secrets and Variables → Actions → New Repository Secret

Required secrets for GitHub Actions deployment:

```
DOCKER_USERNAME=your-dockerhub-username
DOCKER_PASSWORD=your-dockerhub-password
VPS_HOST=your-server-ip
VPS_USERNAME=root
VPS_SSH_KEY=-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

---

## 🔄 CI/CD Workflows

The repository includes GitHub Actions workflows:

| Workflow | File | Description |
|----------|------|-------------|
| Docker Deploy | `.github/workflows/deploy-docker.yml` | Build & push Docker images |
| Render Deploy | `.github/workflows/deploy-render.yml` | Trigger Render deployment |
| Vercel/Netlify | `.github/workflows/deploy-vercel-netlify.yml` | Deploy frontend |

---

## 🌐 Post-Deployment Verification

### Check Backend Health
```bash
curl https://your-backend-url.com/api/health
```

Expected response:
```json
{
  "status": "DFlagger backend running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0"
}
```

### Verify Database Connection
```bash
curl https://your-backend-url.com/api/dashboard/stats
```

### Check Frontend
Open `https://your-frontend-url.com` in browser

---

## 🛠️ Troubleshooting

### Database Connection Issues
```bash
# Check if database is running
docker-compose ps

# View logs
docker-compose logs postgres

# Run migrations manually
docker-compose exec backend npx prisma migrate deploy
```

### CORS Issues
Update `backend/src/server.ts`:
```typescript
app.use(cors({
  origin: 'https://your-frontend-url.com',
  credentials: true
}))
```

### Build Failures
```bash
# Clean rebuild
docker-compose down -v
docker-compose up --build
```

---

## 📊 Monitoring

### Health Check Endpoints
- Backend: `GET /api/health`
- Database: Check connection via `/api/dashboard/stats`

### Logs
```bash
# Backend logs
docker-compose logs -f backend

# Database logs
docker-compose logs -f postgres

# All services
docker-compose logs -f
```

---

## 💰 Cost Estimates (Monthly)

| Platform | Database | Backend | Frontend | Total |
|----------|----------|---------|----------|-------|
| **Render** | $0 (free tier) | $0 (free tier) | $0 (free) | **$0** |
| **Railway** | $5 | $5 | $0 (static) | **$10** |
| **VPS (Hetzner)** | Included | $5 | Included | **$5** |
| **AWS/GCP/Azure** | $15+ | $10+ | $1+ | **$25+** |

---

## 📚 Useful Links

- [Prisma Deployment Guide](https://www.prisma.io/docs/guides/deployment)
- [Render Docs](https://render.com/docs)
- [Railway Docs](https://docs.railway.app)
- [Vercel Docs](https://vercel.com/docs)
- [Docker Docs](https://docs.docker.com)
