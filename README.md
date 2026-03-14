
# DFlagger – Threat Detection Platform

![License](https://img.shields.io/badge/license-MIT-blue)
![Docker](https://img.shields.io/badge/docker-supported-blue)
![Node](https://img.shields.io/badge/node-%3E=18-green)
![PostgreSQL](https://img.shields.io/badge/postgresql-supported-blue)
![Status](https://img.shields.io/badge/status-active-success)

---

# Overview

DFlagger is a **Threat Detection Platform** designed to help security teams to manage a detection rules logic using modern detection engineering methodologies.

The Platform Integrates:

- MITRE ATT&CK mapping
- Red Team adversary simulation
- Sigma rule generation
- YARA rule generation
- Detection use case management
- Detection engineering workflows

This platform is intended for:

- Detection Engineers
- Cyber Security Analysts
- Threat Hunters
- Security Researchers

---

# Support Security Platforms and Parsing

- Cortex XDR
- Fidelis EDR
- Splunk
- IBM QRadar
- LogRhythm
- ArcSight

---

# Features

Detection Engineering:

- Detection Use Case Builder
- MITRE ATT&CK mapping
- Detection lifecycle management

Rule Generation:

- Sigma rule builder
- YARA rule generator

Detection Validation:

- Query builder
- Log parser

Living Off The Land:

- LOLGlobs
- LOLBAS 
- LOLDrivers 
- GTFOBins

MITRE ATT&CK Framework:

- Full section includes all of Threats and Techniques Mapping

Cybersecurity Benchmarks:

- NIST
- ISO 27001
- CIS
- SOC 2
- PCI DSS
- CSA CCM
- GDPR

Activities Section:

- Application Audit Log

Settings Features:

- Profile Settings
- User Management
- Roles & Permissions
- Security Policies "Password Policy, Session Management, IP Allowlist"
- Compliance & Audit Settings
- Data Management "Data Retention Policies (days), Backup Configuration"
- SEIM Integrations "**Under Improvement & Enhancement**"
- API Keys
- System Settings "System Information, Maintenance & Operations, File Upload Configuration"
- Appearance

---

# Future Roadmap:

Planned improvements:

- SEIM Integrations
- Automatic Red Team dataset ingestion
- MITRE ATT&CK coverage dashboard
- Detection validation lab
- Threat hunting analytics
  
---
# Architecture

DFlagger uses a modern **Full-Stack Architecture**.

```
Frontend (React + TypeScript + Vite)
        │
        ▼
Backend API (Node.js + Express)
        │
        ▼
Prisma ORM
        │
        ▼
PostgreSQL Database
```

Docker is used to orchestrate all services.

```
Docker Compose
 ├ PostgreSQL
 ├ Backend API
 └ Frontend UI
```

---

# Screenshots

You can add screenshots of the platform UI here once deployed.

Example sections:

- Dashboard
- Use Case Builder
- Sigma Builder
- YARA Generator
- MITRE ATT&CK Explorer

---

# MITRE ATT&CK Integration

DFlagger contains the **MITRE ATT&CK Enterprise Matrix** allowing detection engineers to map detections directly to adversary techniques.

Example workflow:

```
MITRE Technique
      ↓
Red Team Simulation
      ↓
Detection Query
      ↓
Detection Use Case
```

---

# SOC Detection Lifecycle

DFlagger supports the full detection engineering lifecycle:

```
Threat Intelligence
      ↓
MITRE Technique Mapping
      ↓
Attack Simulation
      ↓
Detection Rule Creation
      ↓
Detection Validation
      ↓
Use Case Management
```

---

# System Requirements

Requirements:

| Requirement | Version |
|-------------|--------|
| Docker | 20+ |
| RAM | 4~8GB |
| Disk | 50>GB |

Optional (for development):

| Tool | Version |
|-----|------|
| Node.js | 18+ |
| npm / npx | included with Node |

---

# Step 1 – Install Docker

## Linux

```
sudo apt update -y
sudo apt install docker.io docker-compose-plugin -y
sudo systemctl start docker
sudo systemctl enable docker
```

Verify installation:

```
docker --version
docker compose version
```

Optional (run docker without sudo):

```
sudo usermod -aG docker $USER
```

Log out and log back in.

---

## macOS

Install Docker Desktop:

https://www.docker.com/products/docker-desktop/

Verify:

```
docker --version
docker compose version
```

---

## Windows

Install Docker Desktop:

https://www.docker.com/products/docker-desktop/

Ensure WSL2 is enabled.

Verify installation:

```
docker --version
docker compose version
```

---

# Step 2 – Clone Repository

```
git clone https://github.com/YOURNAME/DFlagger.git
cd DFlagger
```

---

# Step 3 – Configure Environment

```
cp backend/.env.example backend/.env
```

PostgreSQL Example configuration:
Ensure the IP & port correct in the .env file
```
DATABASE_URL=postgresql://admin:admin@127.0.0.1:5432/dflagger
PORT=4000
```
# Step 4 – Launch Platform

```
docker compose up --build
```

Docker will automatically

1. Start PostgreSQL
2. Build backend container
3. Build frontend container
4. Run Prisma migrations
5. Start API
6. Start UI
---
---

# Access the Platform

Frontend

```
http://localhost:5173
```

Backend API

```
http://localhost:4000/api/health
```

---

# Docker Containers

| Container | Purpose |
|--------|--------|
| postgres | PostgreSQL database |
| dflagger-backend | Express API |
| dflagger-frontend | React UI |

View containers:

```
docker ps
```

---

# Stop Platform

```
docker compose down
```

Remove volumes:

```
docker compose down -v
```

---

# Development Mode (Optional)

Backend

```
cd backend
npm install
npx prisma migrate dev
npm run dev
```

Frontend

```
cd frontend/app
npm install
npm run dev
```
---
# Access PostgreSQL Inside Docker if required major changes:

First check running containers
```
docker ps
```
You should see something like
```
dflagger-db
dflagger-backend
dflagger-frontend
```
Enter the PostgreSQL container
```
docker exec -it dflagger-db psql -U admin -d dflagger
```
Now you are inside PostgreSQL
```
dflagger=#
```
Useful PostgreSQL Commands
List tables
```
\dt
```
---

# Project Structure

```
DFlagger
│
├ backend
│   ├ prisma
│   ├ src
│   │   ├ routes
│   │   ├ middleware
│   │   └ server.ts
│
├ frontend
│   └ app
│       ├ src
│       │   ├ components
│       │   ├ sections
│       │   └ lib
│
├ docker-compose.yml
├ README.md
└ LICENSE
```

---

# Contributing

Contributions are welcome.

Steps:

1. Fork repository
2. Create branch
3. Submit pull request

---

# License

MIT License

---
