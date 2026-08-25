#!/bin/bash
# entrypoint.sh — Permanent fix for the SQLite bind-mount permission class of bug.
#
# ROOT CAUSE (found via reading the actual docker-compose.dev.yml, not
# guessed): both api and worker services already had
# `user: "${UID:-1000}:${GID:-1000}"`, which LOOKS like it unifies
# permissions across both containers. It doesn't reliably work: `$UID`
# is a bash-builtin shell PARAMETER, not an exported environment
# variable, in the vast majority of shell configurations -- `docker
# compose` reads its OWN process environment for `${UID}` substitution,
# which essentially never has UID actually exported into it, so this
# expression silently falls back to the hardcoded default "1000" on
# most machines regardless of the real host user's UID. If host-side
# files (webpent.db, webpent.db-wal, webpent.db-shm, or the memory/
# and output/ directories) end up owned by a DIFFERENT uid — e.g. root,
# if `make dev-init` or `docker-compose up` was ever run with sudo, or
# if Docker auto-created the bind-mount target itself (which happens as
# root, since dockerd runs as root) — then a container process running
# as uid 1000 has read-only access to files it doesn't own, producing
# exactly "sqlite3.OperationalError: attempt to write a readonly
# database" no matter what `user:` directive is configured.
#
# FIX: this script runs as root (the image's actual startup user —
# see the Dockerfile, which no longer sets `USER webpent` directly),
# unconditionally reconciles ownership of every bind-mounted,
# write-needed path to the CONTAINER'S configured runtime user (still
# controllable via docker-compose's `user:` directive, or defaults to
# the `webpent` user baked into the image), and then drops privileges
# via `gosu` before exec'ing the real command. This works correctly on
# every single container start, regardless of what UID owns the files
# on the host, without requiring the operator to get UID/GID env vars
# exported correctly, run any manual chmod/chown, or coordinate
# anything between machines.
set -euo pipefail

# Target user/group to run the actual application as. Defaults to the
# webpent:webpent user baked into the base image (see Dockerfile.base).
# Development bind mounts may be owned by the host user and mode 0700;
# WEBPENT_RUN_AS_UID/GID lets Compose select that non-root host identity
# without chowning the source tree or weakening the root refusal guard.
TARGET_UID="${WEBPENT_RUN_AS_UID:-}"
TARGET_GID="${WEBPENT_RUN_AS_GID:-}"
if [ -n "${TARGET_UID}" ] || [ -n "${TARGET_GID}" ]; then
    if [ -z "${TARGET_UID}" ] || [ -z "${TARGET_GID}" ] || \
       ! [[ "${TARGET_UID}" =~ ^[0-9]+$ ]] || \
       ! [[ "${TARGET_GID}" =~ ^[0-9]+$ ]]; then
        echo "entrypoint.sh: ERROR — WEBPENT_RUN_AS_UID/GID must be numeric and supplied together" >&2
        exit 1
    fi
else
    TARGET_USER="${WEBPENT_RUN_AS_USER:-webpent}"
    if ! id -u "${TARGET_USER}" >/dev/null 2>&1 || ! id -g "${TARGET_USER}" >/dev/null 2>&1; then
        echo "entrypoint.sh: ERROR — runtime user does not exist: ${TARGET_USER}" >&2
        exit 1
    fi
    TARGET_UID="$(id -u "${TARGET_USER}")"
    TARGET_GID="$(id -g "${TARGET_USER}")"
fi
if [ "${TARGET_UID}" = "0" ] && [ "${WEBPENT_ALLOW_ROOT:-false}" != "true" ]; then
    echo "entrypoint.sh: ERROR — refusing to run the application as root" >&2
    exit 1
fi
FAIL_ON_OWNERSHIP_ERROR="${WEBPENT_FAIL_ON_OWNERSHIP_ERROR:-false}"

# Paths that need to be writable by the app process. Only chown paths
# that actually exist (bind mounts may or may not include all of these
# depending on which compose file/service is running) — this script is
# shared by both the api and worker entrypoints.
PATHS_TO_FIX=(
    "/app/webpent.db"
    "/app/webpent.db-wal"
    "/app/webpent.db-shm"
    "/app/memory"
    "/app/output"
)

for p in "${PATHS_TO_FIX[@]}"; do
    if [ -e "$p" ]; then
        # -R for directories is a no-op cost-wise for single files, and
        # correctly recurses into memory/ and output/ subdirectories.
        chown -R "${TARGET_UID}:${TARGET_GID}" "$p" 2>/dev/null || {
            if [ "${FAIL_ON_OWNERSHIP_ERROR}" = "true" ]; then
                echo "entrypoint.sh: ERROR — could not chown $p" >&2
                exit 1
            fi
            echo "entrypoint.sh: WARNING — could not chown $p (continuing; " \
                 "the app itself will surface a clear error if this " \
                 "actually blocks a write)." >&2
        }
    fi
done

# Drop privileges and exec the real command as the target user. `exec
# gosu` replaces this script's process (PID 1) with the target
# process running as the target uid — signals (SIGTERM on
# docker-compose down/stop) go directly to the real app, not to a
# shell wrapper that might not forward them correctly.
exec gosu "${TARGET_UID}:${TARGET_GID}" "$@"
