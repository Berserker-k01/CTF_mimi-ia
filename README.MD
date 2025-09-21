# CTF_mimi ai - Agent Autonome pour Kali Linux

Un agent d'intelligence artificielle autonome conçu pour participer à des compétitions CTF (Capture The Flag) en utilisant les outils de Kali Linux.

## 🔥 Fonctionnalités

- **Autonomie complète** : L'agent prend des décisions et exécute des actions sans intervention humaine
- **Utilisation des outils Kali** : Intégration avec nmap, gobuster, sqlmap, metasploit, etc.
- **Installation automatique** : Peut installer de nouveaux outils selon les besoins
- **Accès web** : Capacité à rechercher et analyser des informations en ligne
- **Mémoire persistante** : Stockage des informations découvertes pour une utilisation future
- **Mode daemon** : Fonctionne en arrière-plan comme un service systemd

## ⚙️ Architecture

L'agent est construit autour de plusieurs composants clés :

- **Core Agent** : Moteur de décision basé sur un LLM (Mistral, Llama, etc.)
- **Shell Controller** : Interface pour exécuter des commandes dans Kali Linux
- **Toolbox Interface** : Abstraction des outils de sécurité courants
- **Memory/Brain** : Stockage persistant des informations et des résultats
- **Terminal UI** : Interface utilisateur en ligne de commande
- **Autonomous Loop** : Boucle d'observation, décision, action et évaluation

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-username/ctf_mimi_ai.git
cd ctf_mimi_ai

# Installer les dépendances
pip install -r requirements.txt

# Vérifier la compatibilité avec Kali Linux
python main.py --check-system
```

## 🖥️ Utilisation

### Mode interactif

```bash
python main.py --target 192.168.1.100
```

### Mode daemon

```bash
# Installer le service systemd
sudo python main.py --install-service

# Démarrer le service
sudo systemctl start ctf-mimi-ai
```

## 🛠️ Structure du projet

```
ctf_mimi_ai/
├── main.py                # Point d'entrée principal
├── core/                  # Modules principaux
│   ├── agent.py           # Agent et boucle autonome
│   ├── shell_controller.py # Contrôleur de shell
│   ├── toolbox.py         # Interface des outils
│   ├── memory.py          # Stockage et mémoire
│   ├── ui.py              # Interface utilisateur
│   └── llm_interface.py   # Interface avec le LLM
├── bin/
│   └── ctf_mimi_ai        # Lanceur CLI (installé vers /usr/local/bin)
├── scripts/
│   ├── install_kali.sh    # Script d'installation sur Kali
│   └── uninstall_kali.sh  # Script de désinstallation
├── deploy/
│   └── ctf-mimi-ai.service # Service systemd
├── data/                  # Données persistantes
└── logs/                  # Journaux d'exécution
```

## 🧩 Installation comme application sur Kali Linux

Prérequis: Kali Linux avec `python3`, `python3-venv`, `python3-pip`.

1) Cloner le projet sur Kali

```bash
git clone https://github.com/votre-username/ctf_mimi_ai.git
cd ctf_mimi_ai
```

2) Installer comme service système (root requis)

```bash
sudo bash scripts/install_kali.sh
```

Ce script va:
- Copier le projet vers `/opt/ctf_mimi_ai`
- Créer un venv et installer les dépendances
- Installer le service systemd `ctf-mimi-ai.service`
- Installer le lanceur CLI `/usr/local/bin/ctf_mimi_ai`

3) Démarrer/arrêter le service

```bash
sudo systemctl start ctf-mimi-ai
sudo systemctl status ctf-mimi-ai
sudo journalctl -u ctf-mimi-ai -f
```

Pour arrêter/désactiver:

```bash
sudo systemctl stop ctf-mimi-ai
sudo systemctl disable ctf-mimi-ai
```

4) Utiliser le lanceur CLI

```bash
ctf_mimi_ai --help
ctf_mimi_ai --target 192.168.1.100 --mode recon \
  --llm-model-type gpt-oss --llm-api-url http://127.0.0.1:1234/v1
```

5) Désinstallation

```bash
sudo bash scripts/uninstall_kali.sh
```

### Configuration du LLM local

Si votre LLM local expose une API compatible OpenAI sur `http://127.0.0.1:1234/v1`, utilisez:

```bash
ctf_mimi_ai --llm-model-type gpt-oss --llm-api-url http://127.0.0.1:1234/v1
```

Si l’API n’est pas compatible OpenAI, vous pouvez supprimer le suffixe `/v1` et l’interface utilisera un format générique (`{"prompt": ...}`):

```bash
ctf_mimi_ai --llm-model-type gpt-oss --llm-api-url http://127.0.0.1:1234
```

### Utiliser un lien (URL) comme cible

Vous pouvez définir une URL de challenge directement en cible. L’agent détecte automatiquement les cibles HTTP/HTTPS et priorise un scan Web en phase de reconnaissance.

Exemples:

```bash
# Lancer en CLI sur une URL de challenge
ctf_mimi_ai --target https://chall.ctf.example.com --mode recon \
  --llm-model-type gpt-oss --llm-api-url http://127.0.0.1:1234/v1

# Cible avec port explicite
ctf_mimi_ai --target http://10.10.11.123:8080 --mode recon

# Depuis le repo sans installation système
python main.py --target https://chall.ctf.example.com --mode recon \
  --llm-model-type gpt-oss --llm-api-url http://127.0.0.1:1234/v1
```

Notes:

- L’URL est normalisée et stockée en base; l’hôte (`netloc`) est conservé.
- En reconnaissance sur URL, l’agent lance en premier un `web_scan` (par défaut `nikto`).
- Assurez-vous que les outils Web nécessaires (nikto, gobuster, wpscan, etc.) sont installés sur Kali.
- Pour des environnements non-OpenAI, utilisez `--llm-api-url http://127.0.0.1:1234` (sans `/v1`).