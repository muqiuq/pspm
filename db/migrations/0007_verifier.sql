-- Verifier model (docs/security-ai-improvements.md §3): its independent second opinion on a block.
ALTER TABLE ai_verdicts ADD COLUMN verify_verdict text;
ALTER TABLE ai_verdicts ADD COLUMN verify_confidence real;
ALTER TABLE ai_verdicts ADD COLUMN verify_reason text;
ALTER TABLE ai_verdicts ADD COLUMN verify_model text;
ALTER TABLE ai_verdicts ADD COLUMN verify_call_id bigint;
