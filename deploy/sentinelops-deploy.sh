#!/usr/bin/env bash
# SentinelOps deploy: downloads a GitHub release and (re)starts ONLY the two sentinelops PM2 processes.
# Usage (from the site folder):  ./deploy/sentinelops-deploy.sh v1.0.0
# It never touches any other app, Apache, the firewall or Docker. Public repo: no login needed.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 vX.Y.Z"; exit 1; }
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "version must look like v1.0.0"; exit 1;; esac

SITE="${SITE:-/var/www/Vhost/jjlltdnext.desss-portfolio.com}"
REPO="chandlerdev/sentinelops"
BASE="https://github.com/$REPO/releases/download/$VERSION"
BACKEND="$SITE/sentinelops_backend"
ADMIN="$SITE/sentinelops_admin"
ECO="$SITE/deploy/sentinelops-ecosystem.config.js"

[ -f "$ECO" ]                          || { echo "missing $ECO (copy the .example and edit it)"; exit 1; }
[ -f "$BACKEND/application.properties" ] || { echo "missing $BACKEND/application.properties (settings file)"; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "== downloading $VERSION"
curl -fSL -o "$TMP/backend.jar"        "$BASE/backend.jar"
curl -fSL -o "$TMP/frontend.tar.gz"    "$BASE/frontend.tar.gz"

echo "== backing up the current version"
STAMP="$(date +%Y%m%d-%H%M%S)"
[ -f "$BACKEND/backend.jar" ] && cp "$BACKEND/backend.jar" "$BACKEND/backend.jar.bak-$STAMP"
if [ -d "$ADMIN/.next" ]; then tar -czf "$ADMIN/.next-backup-$STAMP.tar.gz" -C "$ADMIN" .next; fi

echo "== installing backend"
cp "$TMP/backend.jar" "$BACKEND/backend.jar"

echo "== installing frontend"
rm -rf "$ADMIN/.next"
tar -xzf "$TMP/frontend.tar.gz" -C "$ADMIN"
( cd "$ADMIN" && npm ci --omit=dev --no-audit --no-fund )

echo "== starting / restarting only the sentinelops processes"
pm2 startOrRestart "$ECO" --update-env
pm2 save

# keep only the 3 newest backups of each kind
ls -1t "$BACKEND"/backend.jar.bak-* 2>/dev/null | tail -n +4 | xargs -r rm -f
ls -1t "$ADMIN"/.next-backup-*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f

echo "deploy finished ($VERSION)"
