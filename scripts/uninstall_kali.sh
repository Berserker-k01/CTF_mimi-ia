#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/ctf_mimi_ai"
SERVICE_NAME="ctf-mimi-ai.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
LAUNCHER_BIN="/usr/local/bin/ctf_mimi_ai"

if [ "$(id -u)" -ne 0 ]; then
  echo "Ce script doit être exécuté en tant que root (sudo)." >&2
  exit 1
fi

echo "Arrêt et désactivation du service ..."
systemctl stop "$SERVICE_NAME" || true
systemctl disable "$SERVICE_NAME" || true

if [ -f "$SERVICE_PATH" ]; then
  rm -f "$SERVICE_PATH"
  systemctl daemon-reload
fi

if [ -f "$LAUNCHER_BIN" ]; then
  rm -f "$LAUNCHER_BIN"
fi

if [ -d "$APP_DIR" ]; then
  rm -rf "$APP_DIR"
fi

echo "Désinstallation terminée."
