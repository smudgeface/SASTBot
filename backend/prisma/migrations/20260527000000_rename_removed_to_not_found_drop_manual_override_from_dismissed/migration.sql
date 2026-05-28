-- Rename dismissed_status value 'removed' → 'not_found'
-- 'removed' overstated certainty; the worker writes it when evidence is absent,
-- not when a component is confirmed deleted.
UPDATE scope_components SET dismissed_status = 'not_found' WHERE dismissed_status = 'removed';

-- Clean up 'manual_override' from dismissed_status.
-- This value was never correctly written to dismissed_status — operator edits
-- live on scope_components.source = 'manual_override', not dismissed_status.
-- Any rows with this value (from a prior bug) are reset to 'active'.
UPDATE scope_components SET dismissed_status = 'active' WHERE dismissed_status = 'manual_override';
