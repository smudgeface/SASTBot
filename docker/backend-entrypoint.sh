#!/usr/bin/env bash
#
# SASTBot backend entrypoint — production.
#
# Lifecycle on every container start:
#   1. Take a pg_dump backup of the live DB into BACKUP_DIR.
#   2. Verify the gzip stream with `gunzip -t` (CRC32 of the tarball).
#   3. Rotate older backups to keep at most BACKUP_RETENTION_COUNT.
#   4. Run `prisma migrate deploy`.
#   5. Exec the requested command (server or worker).
#
# Why "every start" and not "every Dokploy deploy specifically": this script
# runs inside the container, so it can't observe Dokploy's deploy events
# directly. A backup on every restart is harmless — the rotation cap keeps
# growth bounded, and a "wasted" backup on an OOM restart is cheaper than
# discovering you skipped backup on the one deploy that needed it.
#
# Failure modes:
#   - pg_dump fails (DB unreachable, disk full, permissions): aborts the
#     deploy unless ALLOW_DEPLOY_WITHOUT_BACKUP=true is set. The new
#     container exits non-zero; Dokploy keeps the old one running.
#   - gunzip -t fails (corrupted tarball): aborts the deploy. The bad
#     tarball is deleted so it doesn't fill rotation slots with garbage.
#   - First boot against an empty DB: pg_dump produces a tiny valid
#     tarball with schema but no data. That's a valid backup of "empty"
#     and the script proceeds normally.
#
# Env vars consumed:
#   DATABASE_URL                  — postgres:// connection string
#   BACKUP_DIR                    — default /backups (matches compose volume)
#   BACKUP_RETENTION_COUNT        — default 10
#   ALLOW_DEPLOY_WITHOUT_BACKUP   — default false; "true" skips the backup
#                                   step (use only when recovering from a
#                                   stuck deploy loop).
#   SASTBOT_TAKE_BACKUP           — default "true". Set to "false" on the
#                                   worker compose service so worker restarts
#                                   don't double-backup with the backend.
#   SASTBOT_RUN_MIGRATIONS        — default "true". Set to "false" on the
#                                   worker compose service so the worker
#                                   doesn't race the backend on migrate deploy.

set -euo pipefail

log() {
  echo "[entrypoint] $*"
}

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_RETENTION_COUNT="${BACKUP_RETENTION_COUNT:-10}"
ALLOW_DEPLOY_WITHOUT_BACKUP="${ALLOW_DEPLOY_WITHOUT_BACKUP:-false}"
SASTBOT_TAKE_BACKUP="${SASTBOT_TAKE_BACKUP:-true}"
SASTBOT_RUN_MIGRATIONS="${SASTBOT_RUN_MIGRATIONS:-true}"

# Parse DATABASE_URL into PG* env vars so pg_dump never sees the password
# on the command line. Mirrors the logic in backend/src/routes/adminBackup.ts.
parse_database_url() {
  local url="${DATABASE_URL:-}"
  if [ -z "$url" ]; then
    log "DATABASE_URL is empty — cannot take backup"
    return 1
  fi

  # Strip the scheme.
  local rest="${url#postgresql://}"
  rest="${rest#postgres://}"

  # Split on '@': "user:pass@host:port/db?args"
  local auth="${rest%%@*}"
  local hostpart="${rest#*@}"

  # Auth = "user:pass" (pass may be missing, with no leading ':')
  local user="${auth%%:*}"
  local pass=""
  if [[ "$auth" == *:* ]]; then
    pass="${auth#*:}"
  fi

  # Hostpart = "host:port/db?args"; strip query string first.
  hostpart="${hostpart%%\?*}"
  local hostport="${hostpart%%/*}"
  local dbname="${hostpart#*/}"

  local host="${hostport%%:*}"
  local port=""
  if [[ "$hostport" == *:* ]]; then
    port="${hostport#*:}"
  fi

  # URL-decode the password (postgres permits special chars after encoding).
  # printf %b handles \xNN but not %NN — convert with sed first.
  pass="$(printf '%b' "$(printf '%s' "$pass" | sed 's/%/\\x/g')")"
  user="$(printf '%b' "$(printf '%s' "$user" | sed 's/%/\\x/g')")"

  export PGHOST="$host"
  export PGUSER="$user"
  export PGPASSWORD="$pass"
  export PGDATABASE="$dbname"
  [ -n "$port" ] && export PGPORT="$port"
}

take_backup() {
  if [ "$ALLOW_DEPLOY_WITHOUT_BACKUP" = "true" ]; then
    log "ALLOW_DEPLOY_WITHOUT_BACKUP=true — skipping pre-deploy backup"
    return 0
  fi

  log "Taking pre-deploy backup..."
  if ! parse_database_url; then
    log "BACKUP FAILED: could not parse DATABASE_URL"
    return 1
  fi

  mkdir -p "$BACKUP_DIR"

  # Per-attempt scratch dir under /tmp; the final tarball lands in BACKUP_DIR.
  local work_dir
  work_dir="$(mktemp -d /tmp/sastbot-backup-XXXXXXXX)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work_dir'" RETURN

  local dump_path="$work_dir/dump.pgcustom"
  local meta_path="$work_dir/metadata.json"

  if ! pg_dump --format=custom --compress=9 --file "$dump_path" 2> "$work_dir/pg_dump.err"; then
    log "BACKUP FAILED: pg_dump exited non-zero. stderr:"
    cat "$work_dir/pg_dump.err" >&2 || true
    return 1
  fi

  if ! node /app/backend/dist/cli/write-backup-metadata.js "$meta_path" 2> "$work_dir/meta.err"; then
    log "BACKUP FAILED: metadata write failed. stderr:"
    cat "$work_dir/meta.err" >&2 || true
    return 1
  fi

  # Filename pattern mirrors the HTTP backup route. Strip colons from the
  # ISO timestamp so it's safe across filesystems.
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
  local schema_short
  schema_short="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"][:14])' "$meta_path" 2>/dev/null || true)"
  if [ -z "$schema_short" ]; then
    # Fallback if python3 isn't present — grep the field out.
    schema_short="$(sed -n 's/.*"schema_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$meta_path" | cut -c1-14)"
  fi
  [ -z "$schema_short" ] && schema_short="unknown"

  local tar_name="sastbot-backup-${timestamp}-${schema_short}.tar.gz"
  local tar_path="$BACKUP_DIR/$tar_name"

  if ! tar -czf "$tar_path" -C "$work_dir" dump.pgcustom metadata.json; then
    log "BACKUP FAILED: tar exited non-zero"
    rm -f "$tar_path"
    return 1
  fi

  # gzip CRC32 integrity check (see CLAUDE.md / Stream 1 plan: "Backup integrity").
  if ! gunzip -t "$tar_path" 2> "$work_dir/gunzip.err"; then
    log "BACKUP FAILED: gunzip -t reports tarball corruption. stderr:"
    cat "$work_dir/gunzip.err" >&2 || true
    rm -f "$tar_path"
    return 1
  fi

  local size
  size="$(stat -c %s "$tar_path" 2>/dev/null || stat -f %z "$tar_path" 2>/dev/null || echo "?")"
  log "Backup ok: $tar_name (${size} bytes)"

  rotate_backups
  return 0
}

rotate_backups() {
  # Keep the N most recent sastbot-backup-*.tar.gz files, delete the rest.
  # find ... -printf is GNU-only; ls -1t works in the Debian slim base.
  local keep="$BACKUP_RETENTION_COUNT"
  local count=0
  while IFS= read -r f; do
    count=$((count + 1))
    if [ "$count" -gt "$keep" ]; then
      log "Rotating out: $(basename "$f")"
      rm -f "$f"
    fi
  done < <(ls -1t "$BACKUP_DIR"/sastbot-backup-*.tar.gz 2>/dev/null || true)
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

if [ "$SASTBOT_TAKE_BACKUP" = "true" ]; then
  if ! take_backup; then
    if [ "$ALLOW_DEPLOY_WITHOUT_BACKUP" = "true" ]; then
      log "Backup failed but ALLOW_DEPLOY_WITHOUT_BACKUP=true — continuing"
    else
      log "Aborting deploy. Set ALLOW_DEPLOY_WITHOUT_BACKUP=true in Dokploy to override."
      exit 1
    fi
  fi
else
  log "SASTBOT_TAKE_BACKUP=$SASTBOT_TAKE_BACKUP — skipping pre-deploy backup (worker boot)"
fi

if [ "$SASTBOT_RUN_MIGRATIONS" = "true" ]; then
  log "Running prisma migrate deploy..."
  pnpm prisma migrate deploy
else
  log "SASTBOT_RUN_MIGRATIONS=$SASTBOT_RUN_MIGRATIONS — skipping migrations (worker boot)"
fi

log "Starting: $*"
exec "$@"
