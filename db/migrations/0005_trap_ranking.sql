-- Honeypots: only the 300 best are active (docs/security-ai-improvements.md §1).
ALTER TABLE traps ADD COLUMN score real NOT NULL DEFAULT 0;   -- distinct attackers × track × scope × recency
ALTER TABLE traps ADD COLUMN rank integer;                    -- 1 = best, among active and eligible traps
ALTER TABLE traps ADD COLUMN eligible_at timestamptz;         -- passed its shadow period: may be active
UPDATE traps SET eligible_at = updated_at WHERE state = 'active';
