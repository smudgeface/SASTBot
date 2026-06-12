# sastbot-update-prod — connection target TEMPLATE

Copy this to `target.local.md` in this same skill directory (gitignored via the
`*.local.md` rule) and fill in the real values for your deployment. Do NOT put real
hosts/paths/credentials in this committed template, and NEVER store the SSH password
anywhere.

```
# Production SSH + compose target for the sastbot-update-prod skill.
HOST=<prod host or IP reachable over the management VPN>
SSH_USER=<ssh username; password is supplied interactively, never stored>
ENV_FILE=<absolute path to the compose .env on the host>
COMPOSE_FILE=<absolute path to docker-compose.yml on the host>
TAG_VAR=<the env variable that holds the image tag, e.g. SASTBOT_IMAGE_TAG>
SUDO=<prefix for file edits / root-only ops: empty if SSH_USER can write ENV_FILE, else "sudo">
DOCKER_USER=<OS user that holds the registry `docker login`; empty if SSH_USER is itself authenticated and in the docker group>
DOCKER_HOME=<home dir of DOCKER_USER, e.g. /home/<user>; only needed when DOCKER_USER is set>
APP_URL=<https URL of the running app, for /version + /healthz verification>
```

Notes:
- `TAG_VAR`, `SUDO`, and `DOCKER_USER` should be confirmed by a one-time read-only
  check on the host before the first real bump: who owns/can-write `ENV_FILE`
  (→ `SUDO`), and which user's `docker login` is authenticated to the registry
  (→ `DOCKER_USER`/`DOCKER_HOME`).
- **Registry-auth gotcha:** a `docker login` is per-OS-user. If the deploy files
  are owned by a dedicated deploy user, `sudo docker compose pull` (as root) reads
  root's empty docker config and fails `Authentication required`. Run docker as
  the authenticated user instead — `SUDO` is for editing `ENV_FILE`, `DOCKER_USER`
  is for running docker. A personal API token may NOT authenticate to the OCI
  registry (different scope than the CI/REST token); don't rely on it. See
  SKILL.md "Registry auth".
- The same `TAG_VAR` drives both `sastbot-backend` and `sastbot-frontend` images.
