#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CTF_mimi ai - Agent autonome pour le pentesting
Un assistant IA qui utilise les outils de Kali Linux pour réaliser des tests d'intrusion
"""

import os
import sys
import time
import logging
import argparse
from colorama import Fore, Style, init

# Import des modules internes
from core.agent import Agent
from core.shell_controller import ShellController
from core.toolbox import Toolbox
from core.memory import Memory
from core.ui import TerminalUI
from core.llm_interface import LLMInterface

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ctf_mimi_ai.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("CTF-MIMI-AI")

# Initialisation de colorama pour les couleurs dans le terminal
init(autoreset=True)

def parse_arguments():
    """Parse les arguments de ligne de commande"""
    parser = argparse.ArgumentParser(description="CTF_mimi ai - Agent autonome pour le pentesting")
    parser.add_argument("--target", "-t", help="Cible à analyser (IP, domaine, URL)")
    parser.add_argument("--mode", "-m", choices=["recon", "exploit", "post", "full"], 
                        default="full", help="Mode d'opération")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
    parser.add_argument("--daemon", "-d", action="store_true", help="Exécuter en tant que daemon")
    # Options LLM
    parser.add_argument("--llm-model-type", default="gpt-oss", help="Type de modèle LLM (ex: gpt-oss, mistral, llama, falcon)")
    parser.add_argument("--llm-api-url", default=None, help="URL de l'API LLM (ex: http://127.0.0.1:1234/v1)")
    parser.add_argument("--llm-api-key", default=None, help="Clé API LLM si nécessaire")
    return parser.parse_args()

def main():
    """Fonction principale"""
    args = parse_arguments()
    
    print(f"{Fore.RED}╔══════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.RED}║{Style.RESET_ALL}          {Fore.CYAN}CTF_mimi ai{Style.RESET_ALL}                    {Fore.RED}║{Style.RESET_ALL}")
    print(f"{Fore.RED}║{Style.RESET_ALL}    {Fore.YELLOW}Agent Autonome de Pentesting{Style.RESET_ALL}        {Fore.RED}║{Style.RESET_ALL}")
    print(f"{Fore.RED}╚══════════════════════════════════════════╝{Style.RESET_ALL}")
    
    # Initialisation des composants
    shell = ShellController()
    memory = Memory()
    toolbox = Toolbox(shell)
    llm = LLMInterface(
        model_type=args.llm_model_type,
        api_url=args.llm_api_url,
        api_key=args.llm_api_key
    )
    ui = TerminalUI()
    
    # Création de l'agent
    agent = Agent(shell, toolbox, memory, llm, ui)
    
    # Démarrage de l'agent
    agent.set_mode(args.mode)
    agent.set_verbose(args.verbose)

    if args.daemon:
        # En mode daemon, on ne peut pas demander une saisie interactive
        if not args.target:
            logger.error("Aucune cible définie en mode daemon. Utilisez --target ou configurez le service.")
            return
        agent.set_target(args.target)
        logger.info("Démarrage en mode daemon")
        try:
            agent.start()
        except Exception as e:
            logger.error(f"Erreur en mode daemon: {e}")
            raise
    else:
        # Mode interactif: si pas de --target, demander un lien/target en boucle
        if not args.target:
            while True:
                try:
                    user_input = input(f"{Fore.CYAN}[CTF_mimi ai]{Style.RESET_ALL} Entrez le lien/IP/nom de domaine du challenge (Entrée pour quitter): ").strip()
                except EOFError:
                    break
                if not user_input:
                    print(f"{Fore.YELLOW}Aucune cible saisie. Fin.{Style.RESET_ALL}")
                    break
                agent.set_target(user_input)
                agent.start()
                # Après la fin d'un challenge, la boucle redemande automatiquement la cible suivante
            return
        else:
            agent.set_target(args.target)
            agent.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Arrêt de l'agent CTF demandé par l'utilisateur{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erreur critique: {str(e)}")
        sys.exit(1)
