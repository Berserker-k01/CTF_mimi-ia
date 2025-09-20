#!/usr/bin/env bash
set -euo pipefail

# Ce script installe CTF_mimi ai sur Kali Linux comme une application système
# - Copie le projet dans /opt/ctf_mimi_ai
# - Crée un venv et installe les dépendances
# - Installe un service systemd (ctf-mimi-ai.service)
# - Installe un lanceur CLI /usr/local/bin/ctf_mimi_ai

APP_DIR="/opt/ctf_mimi_ai"
SERVICE_NAME="ctf-mimi-ai.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
LAUNCHER_BIN="/usr/local/bin/ctf_mimi_ai"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root (sudo)." >&2
    exit 1
  fi
}

copy_project() {
  mkdir -p "$APP_DIR"
  echo "Copie du projet vers $APP_DIR ..."
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude ".git" ./ "$APP_DIR/"
  else
    cp -a ./ "$APP_DIR/"
  fi
}

setup_venv() {
  echo "Création de l'environnement virtuel Python ..."
  apt-get update -y
  apt-get install -y python3-venv python3-pip
  python3 -m venv "$APP_DIR/venv"
  source "$APP_DIR/venv/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install -r "$APP_DIR/requirements.txt"
}

install_service() {
  echo "Installation du service systemd ..."
  if [ -f "$APP_DIR/deploy/ctf-mimi-ai.service" ]; then
    cp "$APP_DIR/deploy/ctf-mimi-ai.service" "$SERVICE_PATH"
  else
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=CTF_mimi ai Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/main.py --daemon
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
  fi
  chmod 644 "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
}

install_launcher() {
  echo "Installation du lanceur CLI ..."
  install -m 0755 "$APP_DIR/bin/ctf_mimi_ai" "$LAUNCHER_BIN" || {
    # fallback si le binaire n'existe pas encore ici
    cat > "$LAUNCHER_BIN" <<'EOB'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/ctf_mimi_ai"
VENV_DIR="$APP_DIR/venv"
PYTHON="$VENV_DIR/bin/python"
if [ -x "$PYTHON" ]; then
  exec "$PYTHON" "$APP_DIR/main.py" "$@"
else
  echo "[CTF_mimi ai] Environnement virtuel introuvable: $PYTHON" >&2
  exit 1
fi
EOB
    chmod +x "$LAUNCHER_BIN"
  }
}

post_install() {
  chown -R root:root "$APP_DIR"
  echo "Installation terminée. Commandes utiles:"
  echo "  - Démarrer le service : systemctl start ${SERVICE_NAME}"
  echo "  - Voir les logs      : journalctl -u ${SERVICE_NAME} -f"
  echo "  - Lancer en CLI      : ctf_mimi_ai --help"
}

main() {
  require_root
  copy_project
  setup_venv
  install_service
  install_launcher
  post_install
}

main "$@"
