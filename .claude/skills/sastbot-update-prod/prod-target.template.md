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
SUDO=<empty if the SSH_USER can edit ENV_FILE + run docker without sudo, else "sudo">
APP_URL=<https URL of the running app, for /version + /healthz verification>
```

Notes:
- `TAG_VAR` and `SUDO` should be confirmed by a one-time read-only check on the
  host (does the user own/​can-write the env file? does `docker compose` work
  without sudo?) before the first real bump.
- The same `TAG_VAR` drives both `sastbot-backend` and `sastbot-frontend` images.
