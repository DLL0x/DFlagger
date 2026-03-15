-- Rename tables from camelCase to snake_case to match Prisma schema
ALTER TABLE "SigmaRule" RENAME TO sigma_rules;
ALTER TABLE "YaraRule" RENAME TO yara_rules;
ALTER TABLE "UseCase" RENAME TO use_cases;

-- Rename indexes
ALTER INDEX "SigmaRule_pkey" RENAME TO sigma_rules_pkey;
ALTER INDEX "YaraRule_pkey" RENAME TO yara_rules_pkey;
ALTER INDEX "UseCase_pkey" RENAME TO use_cases_pkey;
