# M15 — Re-key on restore (cross-MASTER_KEY backup migration)

**Status:** planned (next session). Builds directly on the A work shipped in
v0.18.0 (the `master_key_fingerprint` in backup metadata + the restore-time
mismatch guard). Owner intent: be able to migrate a full backup to a new
installation **without** depending on LMI IT to wrangle `MASTER_KEY`, and
without permanently adopting the source instance's key.

## Problem (recap)

A **full** backup is a `pg_dump` that includes the encryption **canary** and
every **credential ciphertext**, all encrypted under the *source* instance's
`MASTER_KEY`. Restoring onto an instance with a different key:
- fails the canary on next boot → backend refuses to start, and
- leaves every credential undecryptable.

v0.18.0 (A) makes this **fail fast** — a fingerprint mismatch is refused at
restore with an actionable message ("set `MASTER_KEY` to the source value
first"). That's safe but still forces the operator to run the new box under the
*old* key. B removes that constraint by **re-encrypting the key-bound data from
the old key to the new key during restore.**

## Goal

Allow a full restore of a backup taken under `KEY_OLD` onto an instance running
`KEY_NEW`, by supplying `KEY_OLD` at restore time. The restore re-wraps the
canary + credentials `KEY_OLD → KEY_NEW` so the instance keeps its own key and
all secrets remain usable.

## Design

### API
Add an **optional** `old_master_key` field to `POST /api/admin/db/restore`
(multipart form field, base64, validated to decode to 32 bytes — same as
`MASTER_KEY`). Admin-only (already enforced). **Never logged**; zeroed after use.

### Restore flow (mode=full), extending the A guard
1. Validate metadata / format / schema (unchanged).
2. **Fingerprint gate (from A), now with a rewrap branch:**
   - fingerprints **match** → normal restore, no rewrap.
   - fingerprints **differ**:
     - `old_master_key` **absent** → `422` as today (message also mentions the
       `old_master_key` rewrap option).
     - `old_master_key` **present** → verify `masterKeyFingerprint(old_master_key)`
       equals the dump's `master_key_fingerprint`; if not, `422` ("the supplied
       source key does not match this backup"). This avoids a doomed rewrap.
3. `pg_restore` the dump (canary + creds land **`KEY_OLD`-encrypted**).
4. **Rewrap pass** (only when rewrapping), in a single `prisma.$transaction`:
   - sanity-check: decrypt the restored canary with `KEY_OLD`; must equal
     `CANARY_PLAINTEXT`, else abort before touching credentials.
   - for the canary row and every `credentials` row: `decrypt(blob, KEY_OLD)` →
     `encrypt(plaintext, KEY_NEW)` → `UPDATE`.
5. Continue as today (older-schema → `migrate deploy`; artifact overlay; restart).
6. On restart, the instance's current key (`KEY_NEW`) validates the now-rewrapped
   canary and decrypts all credentials.

### New service
`rewrapAllSecrets(oldKey: Buffer, newKey: Buffer): Promise<{credentials: number}>`
in e.g. `services/keyRewrap.ts`. Pure-ish (takes both keys), transactional,
returns counts for the response/audit log.

## Inventory to confirm FIRST (do not assume)
Audit every AES-GCM-encrypted blob in the DB before writing the rewrap pass —
the rewrap MUST cover all of them or it silently half-migrates:
- `grep -rn "encrypt(\|decrypt(" backend/src` → enumerate callers.
- Expected set today: the `canary` table + the `credentials` table
  (`ciphertext`/`nonce`/`tag` columns). `app_settings` references credentials by
  ID (no inline ciphertext) per CLAUDE.md — confirm that's still true.
- If a new encrypted column was added since, the rewrap must include it. Consider
  a single source-of-truth list of `{table, columns}` so future encrypted columns
  are added in one place.

## Atomicity / failure handling
- The rewrap runs **after** `pg_restore`. If it throws, the DB holds
  `KEY_OLD`-encrypted data while the instance runs `KEY_NEW` → broken state.
- Wrap the rewrap in `$transaction` so a partial rewrap rolls back. On failure,
  return `500` with a clear recovery note: the data is intact but `KEY_OLD`-
  encrypted; recover by retrying the restore with `old_master_key`, or by
  temporarily setting `MASTER_KEY=KEY_OLD`.
- Never leave mixed-key rows committed.

## Security
- `old_master_key` is a secret: never log it; scrub from memory after use; it only
  travels over the same admin/HTTPS channel as the upload. Reject in logs/metrics.
- Re-wrapping doesn't weaken at-rest security — output is `KEY_NEW`-encrypted.

## Tests
- `keyRewrap` unit: encrypt under A → rewrap A→B → decrypts under B, fails under A.
- restore integration (extend `adminRestore.test.ts` / `restoreService.test.ts`):
  backup under A restored onto instance with key B —
  (a) `old_master_key=A` → succeeds, canary + creds usable under B;
  (b) wrong `old_master_key` → 422;
  (c) mismatch + no `old_master_key` → 422 (A behavior preserved).

## Frontend
Restore dialog gains an optional **"Source MASTER_KEY (only when restoring a
backup from a different installation)"** field. Nice-to-have: on a 422
key-mismatch, surface the field and let the operator retry with the source key
(two-step). Keep it an advanced/optional input otherwise.

## Versioning / docs
- Operator-visible new capability → **MINOR** bump (all three surfaces) when shipped.
- Update `docs/user-manual/admin-backup-restore.md` (the MASTER_KEY-guard section
  gains the rewrap path) and `docs/DEPLOY_PROXMOX.md` (§9). PROGRESS entry.

## Bonus (consider, don't scope-creep)
The same `rewrapAllSecrets` helper could power a proper **in-place
`MASTER_KEY` rotation** admin endpoint, replacing the manual "delete the canary
row + re-enter every credential" dance documented in
`docs/user-manual/admin-deployment.md`. Note it; decide separately.
