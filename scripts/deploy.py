"""Trigger a Dokploy deploy via webhook.

Reads configuration from environment variables so the same script works for
the homelab instance, LMI's future instance, or any other Dokploy target.
The URL itself is considered sensitive (contains the webhook secret) and
should live in a gitignored file like ``docs/DEPLOY_HOMELAB.md`` or a
shell-exported variable — never committed.

Required env vars:
  DOKPLOY_WEBHOOK_URL   Full POST URL, e.g. http://dokploy.example/api/deploy/compose/<id>

Optional env vars:
  DOKPLOY_REF           Git ref to deploy (default: refs/heads/main)
  DOKPLOY_REPO_FULL     Owner/repo display string (default: smudgeface/SASTBot)

Usage::

    export DOKPLOY_WEBHOOK_URL=http://192.168.20.119:3000/api/deploy/compose/<id>
    python -m scripts.deploy
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from ._console import error, info, section, success


def run() -> int:
    url = os.environ.get("DOKPLOY_WEBHOOK_URL")
    if not url:
        error("DOKPLOY_WEBHOOK_URL is not set.")
        return 2

    ref = os.environ.get("DOKPLOY_REF", "refs/heads/main")
    repo_full = os.environ.get("DOKPLOY_REPO_FULL", "smudgeface/SASTBot")

    body = json.dumps({"ref": ref, "repository": {"full_name": repo_full}}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-github-event": "push"},
    )

    with section(f"POST {url}"):
        info(f"ref={ref}  repo={repo_full}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
                payload = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            error(f"Dokploy returned HTTP {e.code}: {body}")
            return 1
        except urllib.error.URLError as e:
            error(f"Could not reach Dokploy: {e.reason}")
            return 1

    if 200 <= status < 300:
        success(f"Dokploy accepted the deploy request (HTTP {status}).")
        if payload:
            info(payload)
        return 0
    error(f"Unexpected response HTTP {status}: {payload}")
    return 1


if __name__ == "__main__":
    sys.exit(run())
