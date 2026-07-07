-- Component provenance, mirroring threats.source: who put this component in
-- the model. 'manual' (hand-added, the default for every pre-existing row),
-- 'detected' (the deterministic IaC scan), or 'assisted' (LLM-proposed,
-- human-confirmed). The console labels non-manual sources so a reviewer can
-- always tell curated architecture from generated baseline.
ALTER TABLE threat_components ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
