# Repositories

A repository row in SASTBot is the source-of-truth for a Git URL the
worker will clone. It carries the credential, the default branch, the
list of scan paths, and a fair number of knobs for tuning the scan.
Repository CRUD lives at **Admin → Repositories**.

## Creating a repository

1. **Add repository** at the top right of the list.
2. **Name** — your label. Used on the Scopes page row, on scan
   detail, and in SBOM `metadata.component.name`.
3. **URL** — `https://…` or `git@…:…/repo.git`.
4. **Protocol** — `https` or `ssh`. Must match the URL shape; the form
   validates this.
5. **Default branch** — what the worker clones. The runtime model
   doesn't support running the same repo against multiple branches; if
   you need that, add a second repo entry.
6. **Credential** — pick an existing credential whose kind matches the
   URL (`https_token`, `https_basic`, or `ssh_key`), or create one
   inline using the **Create new** tab. See [Credentials](credentials).
7. **Scan paths** — one path per scope you want SASTBot to track. `/`
   is the default; common multi-scope shapes are
   `/`, `/services/api`, `/services/web`, etc.
8. **Ignore paths** — extra paths to exclude from scanning. The LLM
   detection prompt also receives this list explicitly via an
   `IGNORE_PATHS` block, so it'll skip those subtrees as well.
9. **Source URL template** — optional. Supports `$FILE` and `$LINE`
   placeholders. With it, snippet headers in the SAST view become real
   clickable links to your code host (Bitbucket, GitHub, etc.). With
   it empty, paths are plain text.

You can leave most of the advanced knobs at their defaults. The ones
that matter day-to-day:

- **Retain clone** — if on, the working clone is kept after the scan
  finishes. Saves the ~minute of `cloning` on subsequent runs but
  consumes per-repo disk on the worker. Toggle off and the cache is
  purged (since v0.9.7).
- **Reachability enabled** — if off, SCA findings are flat — no LLM
  reachability assessment. Speeds up large scans where reachability
  isn't compliance-relevant.
- **Reachability includes dev deps** — npm-only. Off by default —
  components marked `dev: true` by cdxgen 12.2+ are hidden from
  Components, SCA, and the LLM reachability hints.
- **LLM SAST effort** — claude-p `--effort` for the detection pass.
  Default `xhigh` (Opus). Lower for cheaper / faster scans.
- **LLM recheck effort** — claude-p `--effort` for the recheck pass.
  Default `medium`. Recheck is verification, not search.
- **First-party namespaces** — string list. Names with these prefixes
  are dropped by the LLM SBOM augmentation step as known first-party.
  Set this on every LMI repo at onboarding; with it empty, the LLM has
  to infer first-party status from content inspection, which is more
  expensive and less deterministic.
- **Vendored directories** — string list. Default
  `["extern/", "third-party/", "vendor/"]`. The LLM SBOM augmentation
  scans these for vendored libs cdxgen missed.

## Scope auto-sync

When you save a repo with N scan paths, SASTBot ensures there are
exactly N active scope rows for that repo — one per path. If you remove
a path and re-save, the corresponding scope is *deactivated* (not
deleted) — its issues and history are preserved but it disappears from
the Scopes page. Re-adding the path reactivates it.

## Editing a repository

The same form covers edit. A few specific behaviours:

- Changing **scan paths** runs the scope sync above.
- Changing **default branch** affects the *next* scan only. Existing
  scan rows record what branch they ran against.
- Switching **credential** is immediate. Subsequent clones use the new
  credential; in-flight scans keep their existing one.
- Toggling **retain_clone** from on → off purges the existing clone
  cache directory (best-effort). The DB write is the source of truth.

## Deleting a repository

The trashcan at the right of the row opens a confirm dialog. Delete is
**cascading**:

- All scopes for this repo are deleted (scan_scopes).
- All scan runs are deleted (scan_runs).
- All `sbom_components`, `scope_components`, `sast_issues`, `sca_issues`
  rows are deleted.
- Every per-scan artifact file (`sbom/*.json`, `sarif/*.sarif.json`) on
  disk is removed.
- The retained clone cache directory is purged from
  `/app/clones/<repoId>` if `retain_clone` was on.

No undo. If you want to disable a repo without losing history, toggle
**Is active** off instead — the repo stays in place but the Scopes page
won't surface it.

## Trying a connection without scanning

Each row's dropdown menu has a **Check connection** action. It runs the
equivalent of `git ls-remote` against the configured URL with the
configured credential and reports back with the latency and the resolved
default-branch SHA. Useful for verifying VPN reachability before
committing to a real scan.

## Purging the clone cache

`Purge cache` (on the row dropdown) is a manual escape hatch. Removes
the on-disk clone directory for this repo without otherwise touching
state. The next scan re-clones from scratch. Mostly useful when the
clone has become corrupt or when you've deleted the credential and
want to ensure no auth tokens remain on disk.
