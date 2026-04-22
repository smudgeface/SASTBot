"""Integration test: exercise all three git-auth credential kinds against a real Gitea.

Brings up a gitea container (via the overlay compose file), provisions an
admin user with an access token + SSH key + sample repository, then drives
the SASTBot API to:

  1. create a credential of each kind (https_token, https_basic, ssh_key)
  2. register a repo pointing at the gitea instance, referencing that credential
  3. trigger a scan and wait for it to land in `success`

On failure the script prints the failing scan's error and exits non-zero.

Usage::

    python -m scripts.integration_gitea
    python -m scripts.integration_gitea --keep       # leave gitea up after the test
    python -m scripts.integration_gitea --teardown   # just tear down the overlay

Requires the core compose stack (`docker compose -f docker/compose/docker-compose.yml up -d`)
to be running. The script brings up the gitea overlay itself.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ._console import error, info, run_cmd, section, success

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPOSE_MAIN = "docker/compose/docker-compose.yml"
COMPOSE_GITEA = "docker/compose/docker-compose.gitea.yml"
ENV_FILE = ".env"

# Host-side access to gitea (via the port-mapping in the overlay).
GITEA_HOST_HTTP = "http://localhost:3100"
# Compose-network access (what the SASTBot worker uses to clone).
GITEA_INTERNAL_HTTP = "http://gitea:3000"
GITEA_INTERNAL_SSH_HOST = "gitea"
GITEA_INTERNAL_SSH_PORT = 22
# Sample repo owner/name/branch — must match the Gitea auto_init defaults.
REPO_OWNER = "sastbot"
REPO_BRANCH = "main"
# One gitea repo per auth kind — the SASTBot unique (org_id, url) constraint
# prevents us from registering the same URL three times.
REPO_NAMES = {
    "https_token": "sample-token",
    "https_basic": "sample-basic",
    "ssh_key": "sample-ssh",
}

# Admin user that we create in gitea + use to drive its API.
ADMIN_USER = "sastbot"
ADMIN_PASS = "sastbotpass"  # noqa: S105 — local test only, never committed secrets
ADMIN_EMAIL = "sastbot@gitea.local"

SASTBOT_BASE = "http://localhost:8000"
SASTBOT_ADMIN_EMAIL = "admin@sastbot.local"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def compose(*args: str) -> list[str]:
    """Build a `docker compose` argv that includes both compose files and .env."""
    return [
        "docker",
        "compose",
        "-f",
        COMPOSE_MAIN,
        "-f",
        COMPOSE_GITEA,
        "--env-file",
        ENV_FILE,
        *args,
    ]


def run_compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd(compose(*args), check=check)


def exec_in_gitea(cmd: str) -> str:
    """Run *cmd* as root inside the gitea container and return stdout."""
    result = subprocess.run(
        compose("exec", "-T", "gitea", "sh", "-c", cmd),
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def exec_in_backend(cmd: str) -> str:
    """Run *cmd* inside the backend container (for ssh-keyscan / diagnostics)."""
    result = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_MAIN, "--env-file", ENV_FILE,
         "exec", "-T", "backend", "sh", "-c", cmd],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout


def http_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
    cookie: str | None = None,
    timeout: float = 15.0,
    raise_for_status: bool = True,
) -> tuple[int, Any]:
    """Tiny HTTP client — JSON in, JSON out. Returns (status, parsed_body_or_None)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req_headers = {"Accept": "application/json"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    if cookie:
        req_headers["Cookie"] = cookie
    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    if basic_auth:
        import base64
        token = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read()
        if raise_for_status:
            raise RuntimeError(
                f"HTTP {status} from {method} {url}: {raw.decode('utf-8', errors='replace')}",
            ) from e
    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            parsed = raw.decode("utf-8", errors="replace")
    return status, parsed


# ---------------------------------------------------------------------------
# Gitea provisioning
# ---------------------------------------------------------------------------


def start_gitea() -> None:
    with section("bring up gitea overlay"):
        run_compose("up", "-d", "gitea")

    with section("wait for gitea API"):
        # Gitea cold-starts slowly the first time (DB init, SSH key gen,
        # asset extraction). Be patient on a fresh volume.
        deadline = time.monotonic() + 180.0
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                status, _ = http_json(
                    f"{GITEA_HOST_HTTP}/api/v1/version",
                    timeout=3.0,
                    raise_for_status=False,
                )
                if status == 200:
                    info("gitea is serving /api/v1/version")
                    return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
            time.sleep(1.0)
        raise TimeoutError(f"gitea did not become healthy in 60s (last: {last_err})")


def ensure_admin_user() -> None:
    with section(f"ensure gitea admin user '{ADMIN_USER}'"):
        # `gitea admin user create` fails (non-zero) if the user already exists.
        # We want the step to be idempotent, so we check-then-create.
        try:
            stdout = exec_in_gitea(
                f"su git -c 'gitea admin user list' 2>/dev/null",
            )
        except subprocess.CalledProcessError as exc:
            stdout = exc.stdout or ""

        if ADMIN_USER in stdout:
            info(f"user '{ADMIN_USER}' already exists")
            return

        cmd = (
            f"su git -c 'gitea admin user create "
            f"--username {ADMIN_USER} "
            f"--password {ADMIN_PASS} "
            f"--email {ADMIN_EMAIL} "
            f"--admin "
            f"--must-change-password=false'"
        )
        subprocess.run(
            compose("exec", "-T", "gitea", "sh", "-c", cmd),
            check=True,
            text=True,
        )
        info(f"created admin user '{ADMIN_USER}'")


def ensure_repos() -> None:
    with section("ensure gitea repos (one per auth kind)"):
        for name in REPO_NAMES.values():
            status, payload = http_json(
                f"{GITEA_HOST_HTTP}/api/v1/repos/{REPO_OWNER}/{name}",
                basic_auth=(ADMIN_USER, ADMIN_PASS),
                raise_for_status=False,
            )
            if status == 200:
                info(f"repo '{REPO_OWNER}/{name}' exists")
                continue
            if status != 404:
                raise RuntimeError(
                    f"unexpected status checking repo {name}: {status} {payload}",
                )
            http_json(
                f"{GITEA_HOST_HTTP}/api/v1/user/repos",
                method="POST",
                body={
                    "name": name,
                    "auto_init": True,
                    "default_branch": REPO_BRANCH,
                    "private": False,
                },
                basic_auth=(ADMIN_USER, ADMIN_PASS),
            )
            info(f"created repo '{REPO_OWNER}/{name}' with auto_init")


def ensure_access_token() -> str:
    with section("gitea access token"):
        # Listing tokens is cheap; delete any old `sastbot-integration` so we
        # get a fresh one whose plaintext we can read.
        status, tokens = http_json(
            f"{GITEA_HOST_HTTP}/api/v1/users/{ADMIN_USER}/tokens",
            basic_auth=(ADMIN_USER, ADMIN_PASS),
        )
        for t in tokens or []:
            if t.get("name") == "sastbot-integration":
                http_json(
                    f"{GITEA_HOST_HTTP}/api/v1/users/{ADMIN_USER}/tokens/sastbot-integration",
                    method="DELETE",
                    basic_auth=(ADMIN_USER, ADMIN_PASS),
                    raise_for_status=False,
                )

        _, created = http_json(
            f"{GITEA_HOST_HTTP}/api/v1/users/{ADMIN_USER}/tokens",
            method="POST",
            body={
                "name": "sastbot-integration",
                "scopes": ["write:repository", "read:user"],
            },
            basic_auth=(ADMIN_USER, ADMIN_PASS),
        )
        sha = created["sha1"]
        info("minted access token (plaintext available once)")
        return sha


def generate_ssh_keypair(workdir: Path) -> tuple[str, str]:
    """Generate an ed25519 keypair in *workdir* and return (private_pem, public_line)."""
    with section("generate ed25519 SSH keypair"):
        key_path = workdir / "id_ed25519"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "sastbot-integration",
                "-f",
                str(key_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        private = key_path.read_text()
        public = (workdir / "id_ed25519.pub").read_text().strip()
        return private, public


def ensure_ssh_key_uploaded(public_key: str) -> None:
    with section("upload SSH public key to gitea"):
        # Re-upload is idempotent-ish: gitea rejects duplicates with 422.
        _, keys = http_json(
            f"{GITEA_HOST_HTTP}/api/v1/users/{ADMIN_USER}/keys",
            basic_auth=(ADMIN_USER, ADMIN_PASS),
        )
        title = "sastbot-integration"
        for k in keys or []:
            if k.get("title") == title:
                http_json(
                    f"{GITEA_HOST_HTTP}/api/v1/user/keys/{k['id']}",
                    method="DELETE",
                    basic_auth=(ADMIN_USER, ADMIN_PASS),
                    raise_for_status=False,
                )
        http_json(
            f"{GITEA_HOST_HTTP}/api/v1/user/keys",
            method="POST",
            body={"title": title, "key": public_key},
            basic_auth=(ADMIN_USER, ADMIN_PASS),
        )
        info("uploaded SSH key to gitea")


def fetch_known_hosts_from_backend() -> str:
    """Run ssh-keyscan inside the backend container — that's the host from
    which the worker will eventually connect, so its known_hosts view is
    what matters for the worker's subsequent clones."""
    with section("ssh-keyscan gitea (from backend container)"):
        output = exec_in_backend(
            f"ssh-keyscan -T 10 -p {GITEA_INTERNAL_SSH_PORT} {GITEA_INTERNAL_SSH_HOST} 2>/dev/null",
        )
        if not output.strip():
            raise RuntimeError("ssh-keyscan returned no host keys")
        return output.strip()


# ---------------------------------------------------------------------------
# SASTBot driver
# ---------------------------------------------------------------------------


def sastbot_login() -> str:
    """Create a one-off admin via the CLI, then log in to SASTBot; return the
    `Cookie` header value for subsequent calls."""
    with section("create + log in as a SASTBot admin"):
        email = f"integration-{secrets.token_hex(3)}@sastbot.local"
        result = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_MAIN, "--env-file", ENV_FILE,
             "exec", "-T", "backend", "pnpm", "run", "bootstrap-admin",
             "--email", email],
            check=True,
            text=True,
            capture_output=True,
        )
        password = None
        for line in result.stdout.splitlines():
            if "password:" in line:
                password = line.split("password:")[-1].strip()
        if not password:
            raise RuntimeError(f"could not parse bootstrap password: {result.stdout}")
        info(f"admin: {email}")

        # Log in
        req = urllib.request.Request(
            f"{SASTBOT_BASE}/auth/login",
            data=json.dumps({"email": email, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            set_cookie = resp.headers.get("Set-Cookie", "")
        if "sastbot_session=" not in set_cookie:
            raise RuntimeError(f"no session cookie in response: {set_cookie}")
        cookie = set_cookie.split(";")[0]
        return cookie


def create_credential(cookie: str, body: dict[str, Any]) -> str:
    _, resp = http_json(
        f"{SASTBOT_BASE}/admin/credentials",
        method="POST",
        body=body,
        cookie=cookie,
    )
    return resp["id"]


def create_repo(
    cookie: str,
    *,
    name: str,
    url: str,
    protocol: str,
    credential_id: str,
) -> str:
    _, resp = http_json(
        f"{SASTBOT_BASE}/admin/repos",
        method="POST",
        body={
            "name": name,
            "url": url,
            "protocol": protocol,
            "default_branch": REPO_BRANCH,
            "scan_paths": ["/"],
            "analysis_types": ["sca"],
            "retain_clone": False,
            "credential_id": credential_id,
        },
        cookie=cookie,
    )
    return resp["id"]


def trigger_scan_and_wait(cookie: str, repo_id: str, *, name: str) -> None:
    _, scan = http_json(
        f"{SASTBOT_BASE}/admin/repos/{repo_id}/scan",
        method="POST",
        cookie=cookie,
    )
    scan_id = scan["id"]
    info(f"{name}: queued scan {scan_id}")
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        _, got = http_json(
            f"{SASTBOT_BASE}/scans/{scan_id}",
            cookie=cookie,
        )
        status = got["status"]
        if status == "success":
            info(f"{name}: success ({got['finished_at']})")
            return
        if status == "failed":
            raise RuntimeError(f"{name}: scan failed — {got.get('error')}")
        time.sleep(1.0)
    raise TimeoutError(f"{name}: scan did not finish in 90s")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def teardown() -> None:
    with section("tear down gitea overlay"):
        run_compose("down", "gitea", check=False)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise HTTPS-token, HTTPS-basic and SSH-key clones against a real gitea.",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Leave the gitea overlay running after the test.",
    )
    parser.add_argument(
        "--teardown",
        action="store_true",
        help="Tear down the gitea overlay and exit (no test).",
    )
    args = parser.parse_args(argv)

    if args.teardown:
        teardown()
        return 0

    if not shutil.which("ssh-keygen"):
        error("ssh-keygen is required on the host to generate the integration key pair")
        return 2

    workdir = Path(tempfile.mkdtemp(prefix="sastbot-integration-"))
    try:
        start_gitea()
        ensure_admin_user()
        ensure_repos()
        token = ensure_access_token()
        private_pem, public_line = generate_ssh_keypair(workdir)
        ensure_ssh_key_uploaded(public_line)
        known_hosts = fetch_known_hosts_from_backend()

        cookie = sastbot_login()

        with section("HTTPS token: create cred + repo + scan"):
            cred = create_credential(
                cookie,
                {"kind": "https_token", "label": "gitea-token", "value": token},
            )
            repo_id = create_repo(
                cookie,
                name="gitea-https-token",
                url=f"{GITEA_INTERNAL_HTTP}/{REPO_OWNER}/{REPO_NAMES['https_token']}.git",
                protocol="https",
                credential_id=cred,
            )
            trigger_scan_and_wait(cookie, repo_id, name="https_token")

        with section("HTTPS basic: create cred + repo + scan"):
            cred = create_credential(
                cookie,
                {
                    "kind": "https_basic",
                    "label": "gitea-basic",
                    "username": ADMIN_USER,
                    "password": ADMIN_PASS,
                },
            )
            repo_id = create_repo(
                cookie,
                name="gitea-https-basic",
                url=f"{GITEA_INTERNAL_HTTP}/{REPO_OWNER}/{REPO_NAMES['https_basic']}.git",
                protocol="https",
                credential_id=cred,
            )
            trigger_scan_and_wait(cookie, repo_id, name="https_basic")

        with section("SSH key: create cred + repo + scan"):
            cred = create_credential(
                cookie,
                {
                    "kind": "ssh_key",
                    "label": "gitea-ssh",
                    "private_key": private_pem,
                    "known_hosts": known_hosts,
                },
            )
            repo_id = create_repo(
                cookie,
                name="gitea-ssh",
                url=f"git@{GITEA_INTERNAL_SSH_HOST}:{REPO_OWNER}/{REPO_NAMES['ssh_key']}.git",
                protocol="ssh",
                credential_id=cred,
            )
            trigger_scan_and_wait(cookie, repo_id, name="ssh_key")

        success("\n✔ all three auth methods clone cleanly against a real gitea")
        if not args.keep:
            teardown()
        return 0
    except Exception as exc:  # noqa: BLE001
        error(f"integration test failed: {exc}")
        if not args.keep:
            teardown()
        return 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run())
