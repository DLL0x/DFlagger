#!/bin/bash

echo "=== Fixing Database Tables ==="

# 1. Delete migration records
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "DELETE FROM _prisma_migrations;"

# 2. Rename tables from camelCase to snake_case
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "
ALTER TABLE \"SigmaRule\" RENAME TO sigma_rules;
ALTER TABLE \"YaraRule\" RENAME TO yara_rules;
ALTER TABLE \"UseCase\" RENAME TO use_cases;
ALTER TABLE \"User\" RENAME TO users_table;
"

# 3. Add missing columns to sigma_rules
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "
ALTER TABLE sigma_rules 
  ADD COLUMN IF NOT EXISTS level TEXT DEFAULT 'medium',
  ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'experimental',
  ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS author TEXT DEFAULT 'Security Analyst',
  ADD COLUMN IF NOT EXISTS \"references\" TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS logsource JSONB,
  ADD COLUMN IF NOT EXISTS detection JSONB,
  ADD COLUMN IF NOT EXISTS condition TEXT,
  ADD COLUMN IF NOT EXISTS fields TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS falsepositives TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS \"updatedAt\" TIMESTAMP(3);
"

# 4. Add missing columns to yara_rules
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "
ALTER TABLE yara_rules 
  ADD COLUMN IF NOT EXISTS level TEXT DEFAULT 'high',
  ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS author TEXT DEFAULT 'Security Analyst',
  ADD COLUMN IF NOT EXISTS strings JSONB,
  ADD COLUMN IF NOT EXISTS condition TEXT,
  ADD COLUMN IF NOT EXISTS imports TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS version TEXT DEFAULT '1.0',
  ADD COLUMN IF NOT EXISTS reference TEXT,
  ADD COLUMN IF NOT EXISTS hash TEXT,
  ADD COLUMN IF NOT EXISTS \"updatedAt\" TIMESTAMP(3);
"

# 5. Add missing columns to use_cases
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "
ALTER TABLE use_cases 
  ADD COLUMN IF NOT EXISTS \"mitreTactic\" TEXT,
  ADD COLUMN IF NOT EXISTS \"mitreTechnique\" TEXT,
  ADD COLUMN IF NOT EXISTS platform TEXT DEFAULT 'windows',
  ADD COLUMN IF NOT EXISTS logsource TEXT,
  ADD COLUMN IF NOT EXISTS \"detectionLogic\" JSONB,
  ADD COLUMN IF NOT EXISTS falsepositives TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'draft',
  ADD COLUMN IF NOT EXISTS priority TEXT DEFAULT 'medium',
  ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS author TEXT DEFAULT 'Security Analyst',
  ADD COLUMN IF NOT EXISTS tests JSONB,
  ADD COLUMN IF NOT EXISTS \"updatedAt\" TIMESTAMP(3);
"

echo "=== Verifying Tables ==="
sudo docker exec dflagger-db psql -U postgres -d dflagger -c "\dt"

echo "=== Restarting Backend ==="
sudo docker restart dflagger-backend dflagger-prisma-studio

echo "=== Done! Wait 10 seconds for services to start ==="
sleep 10

# Verify
echo "=== Testing API ==="
curl -s http://localhost:4000/api/health
echo ""
curl -s http://localhost:4000/api/sigma | head -50
