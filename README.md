# DFlagger

DFlagger is a comprehensive detection engineering platform with an enhanced backend supporting:
- Dashboard with real-time analytics
- Use Case Builder with MITRE ATT&CK mapping
- YARA Rule Generator
- Sigma Rule Builder
- Activity/Audit Logs
- Settings & User Management

## 🚀 Quick Start

### Requirements
- Docker & Docker Compose

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/DFlagger.git
cd DFlagger

# Run setup script
./setup.sh
```

### Access

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:4000 |
| Health Check | http://localhost:4000/api/health |

## 📊 Management Commands

```bash
# View logs
docker-compose logs -f

# Stop
docker-compose down

# Restart
docker-compose restart

# Full reset (removes data)
docker-compose down -v
```

## 🏗️ Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Frontend   │──────▶│   Backend   │──────▶│  PostgreSQL │
│   :3000     │      │   :4000     │      │   :5432     │
└─────────────┘      └─────────────┘      └─────────────┘
```

## 🛠️ Tech Stack

- **Frontend**: React + TypeScript + Tailwind CSS
- **Backend**: Node.js + Express + TypeScript
- **Database**: PostgreSQL + Prisma ORM

## 📁 Project Structure

```
DFlagger/
├── backend/           # API server
│   ├── src/routes/    # API endpoints
│   └── prisma/        # Database schema
├── frontend/          # React app
│   └── app/src/       # Source code
├── docker-compose.yml # Docker config
└── setup.sh           # One-click setup
```

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Find and kill process on port 3000
sudo lsof -ti:3000 | xargs kill -9
```

### Rebuild from Scratch
```bash
docker-compose down -v
docker-compose up --build -d
```

### View Logs
```bash
docker-compose logs -f
```
