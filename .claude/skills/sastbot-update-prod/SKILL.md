---
name: sastbot-update-prod
description: >-
  Update (or roll back) the SASTBot PRODUCTION deployment to a specified
  released image tag. Production runs an IT-managed docker-compose stack on a
  Proxmox host that pulls pre-built images from the Bitbucket Packages registry;
  bumping the version = changing one tag variable in the host .env and running
  `docker compose pull && up -d`. Use when the operator says "update/bump/deploy
  prod to X.Y.Z", "roll prod back to ...", or "ship <tag> to production". This
  only swaps the running image tag — it does NOT build images (the Pipelines tag
  build does that) and does NOT itself run migrations (the backend container runs
  `prisma migrate deploy` on boot).
---

# Update SASTBot production to a released image tag

This procedure changes the production deployment's image tag. It is **outward,
hard-to-reverse infrastructure work** — confirm with the operator before the
mutating step, every time.

## Connection target (never hard-coded here)

The concrete host, SSH user, file paths, the exact tag variable name, and whether
commands need `sudo` are **machine/deployment-specific and intentionally NOT in
this committed file** (this skill mirrors to a public repo). Read them from the
gitignored sidecar co-located with this skill:

```
${CLAUDE_SKILL_DIR}/target.local.md
```

(`*.local.md` is gitignored, so this file is never committed.) If it is missing,
STOP and ask the operator to create it from `${CLAUDE_SKILL_DIR}/prod-target.template.md`. Expect it to define:

- `HOST`, `SSH_USER` — SSH target (password supplied interactively, never stored).
- `ENV_FILE`, `COMPOSE_FILE` — absolute paths to the compose env + YAML on the host.
- `TAG_VAR` — the env variable holding the image tag (e.g. `SASTBOT_IMAGE_TAG`).
- `SUDO` — prefix for **file edits and root-only ops** (empty string or `sudo`);
  used for the `sed` on `ENV_FILE` and any read-only inspection root needs. NOT
  for docker — see "Registry auth" below.
- `DOCKER_USER`, `DOCKER_HOME` — the OS user (and its `$HOME`) that holds the
  registry `docker login`; all `docker`/`docker compose` commands run as this
  user. Leave `DOCKER_USER` empty when `SSH_USER` is itself registry-authenticated
  and in the `docker` group. See "Registry auth" below.
- `APP_URL` — the app's HTTPS URL, for `/version` + `/healthz` verification.

## Auth — the SSH password is never stored

The prod SSH password is not in this repo, the sidecar, or memory. Get it from the
operator at invocation and use it without persisting:

- Preferred: ask the operator to run the mutating command themselves via the `!`
  prefix (interactive password), and you drive/verify around it; **or**
- If the operator hands you the password for this run, use `sshpass` via an env
  var you set inline and never echo (`SSHPASS=… sshpass -e ssh …`). Do not write
  it to any file, log, or commit.

## Registry auth — run docker as the user that holds the login (gotcha)

A `docker login` is **per-OS-user**: the credential lives in that user's
`$HOME/.docker/config.json`. On a hardened / IT-managed host the deploy files
(`.env`, compose) are commonly owned by a dedicated deploy user, while your
`SSH_USER` only has `sudo`. Two traps follow:

- **`sudo docker compose pull` runs docker as root**, so it reads *root's* docker
  config — usually empty — and fails with `Authentication required`, even though
  the deploy user can pull fine. Running docker via `sudo` to root is the wrong
  move unless root itself holds the registry login.
- A **personal API token may not authenticate to the container (OCI) registry** —
  its scope can differ from the CI / REST-API token used to check Pipelines. Don't
  `docker login` with it as a workaround; use the existing authenticated user's
  login.

So split privileges by command:

- **File edits** (`sed` on `ENV_FILE`) → `${SUDO}` (root).
- **All docker commands** → run as the registry-authenticated user. Define
  **`${DOCKER}`** as the invocation up to `docker compose`:
  - `DOCKER_USER` set → `${SUDO} -u ${DOCKER_USER} env HOME=${DOCKER_HOME} docker compose`
    (`HOME=${DOCKER_HOME}` makes docker read that user's authenticated config; the
    user's `docker`-group membership grants daemon access).
  - `DOCKER_USER` empty → `docker compose`, run plainly as `SSH_USER` with **no**
    `sudo` — sudo-to-root would drop `SSH_USER`'s login.

  Procedure steps then append the usual `-f ${COMPOSE_FILE} --env-file ${ENV_FILE}
  <cmd>`. `${SUDO}` stays the root prefix for the `sed` edit only.

## Preconditions (verify before proposing the change)

1. **The target tag exists in the registry.** It must have been built+published by
   the Bitbucket Pipelines tag build (`crg.apkg.io/<workspace>/sastbot-{backend,
   frontend}:<tag>`). Confirm the `v<tag>` Pipelines build is green (the
   `sastbot-bitbucket` keychain token + the pipelines REST API can check this) or
   ask the operator to confirm. Never point prod at an unbuilt tag.
2. **Schema compatibility.** A tag with no new Prisma migration is a pure image
   swap. A tag that ADDS a migration will run `prisma migrate deploy` on backend
   boot — fine for forward moves, but a **rollback to an older tag whose schema is
   behind the live DB can fail or misbehave**. Check whether the target tag's
   `backend/prisma/migrations/` differs from what's deployed; flag any rollback
   that crosses a migration to the operator before proceeding.
3. The operator has explicitly named the target tag.

## Procedure

Substitute `HOST`, `SSH_USER`, `ENV_FILE`, `COMPOSE_FILE`, `TAG_VAR`, `SUDO`,
`DOCKER_USER`, `DOCKER_HOME` from the sidecar, and resolve `${DOCKER}` per
"Registry auth" above. `NEW_TAG` is the operator-specified version (no leading
`v`). Reminder: `${SUDO}` is for the `sed` only; every docker command uses
`${DOCKER}`.

1. **Read current state (read-only).** SSH in and capture the *current* tag value
   (this is your rollback target) and the running image tags:
   ```sh
   ${SUDO} grep -E "^${TAG_VAR}=" ${ENV_FILE}
   ${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} ps --format '{{.Service}} {{.Image}}'
   ```
   Record the current tag as `OLD_TAG`.

2. **CONFIRM (gate).** Show the operator: `OLD_TAG → NEW_TAG`, the host, and the
   precondition results (build green? migration crossed?). Get an explicit
   go-ahead before any write. This gate is mandatory — a version bump is not
   standing permission to deploy.

3. **Set the tag.** Edit only the one variable in the env file:
   ```sh
   ${SUDO} sed -i -E "s|^${TAG_VAR}=.*|${TAG_VAR}=${NEW_TAG}|" ${ENV_FILE}
   ${SUDO} grep -E "^${TAG_VAR}=" ${ENV_FILE}   # confirm it now reads NEW_TAG
   ```

4. **Pull + recreate.** This is the deploy (docker as the authenticated user):
   ```sh
   ${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} pull && \
   ${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d
   ```

5. **Verify.** Confirm the new tag is actually live:
   - `${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} ps` → all
     services `Up`/healthy on the `:${NEW_TAG}` image.
   - App reports the new version: `curl -s https://<app-host>/version` (app host is
     in the sidecar) → `.app == NEW_TAG`, and `/healthz` is green. The backend ran
     `prisma migrate deploy` on boot — confirm `schema == expected_schema` in the
     `/version` payload (no amber drift).

6. **Rollback (only if verify fails).** Revert the variable and recreate:
   ```sh
   ${SUDO} sed -i -E "s|^${TAG_VAR}=.*|${TAG_VAR}=${OLD_TAG}|" ${ENV_FILE}
   ${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} pull && \
   ${DOCKER} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d
   ```
   Then report the failure and the logs (`${DOCKER} … logs --tail=100 backend worker`).

## After a successful update

- Tell the operator the old → new tag and that `/version` confirms it.
- If this deploy carried a data-healing worker backfill or other one-time
  migration-by-boot behavior, note that it ran.
- Record the deploy in the deploy-trajectory notes/memory (date, tag, what shipped)
  — but keep host/IP/path details out of any committed file.

## Guardrails

- Read-only inspection is always safe; the `sed` edit and `pull && up -d` are the
  only mutating steps and both require the confirmation gate in step 2.
- Never commit or echo the SSH password.
- Never point prod at a tag whose Pipelines build isn't green.
- Don't run docker via `sudo` to root when a non-root user holds the registry
  login — root's empty docker config makes `pull` fail `Authentication required`.
  Use `${DOCKER}` (the authenticated user); `${SUDO}` is for the `sed` edit only.
  See "Registry auth".
- One variable, two services: the same `TAG_VAR` drives both `sastbot-backend` and
  `sastbot-frontend` images — they move together. Don't split them.
