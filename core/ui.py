#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UI - Interface utilisateur pour l'agent CTF
"""

import sys
import time
import logging
from typing import Optional
from colorama import Fore, Back, Style, init

# Initialisation de colorama
init(autoreset=True)

logger = logging.getLogger("CTF-MIMI-AI.UI")

class TerminalUI:
    """
    Interface utilisateur en terminal pour l'agent CTF
    """
    
    def __init__(self):
        """Initialise l'interface utilisateur"""
        self.last_status = ""
    
    def info(self, message: str):
        """
        Affiche un message d'information
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.info(message)
    
    def success(self, message: str):
        """
        Affiche un message de succès
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.info(message)
    
    def warning(self, message: str):
        """
        Affiche un message d'avertissement
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.warning(message)
    
    def error(self, message: str):
        """
        Affiche un message d'erreur
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.RED}[-] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.error(message)
    
    def thinking(self, message: str):
        """
        Affiche un message de réflexion
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.CYAN}[?] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.info(f"Thinking: {message}")
    
    def action(self, message: str):
        """
        Affiche un message d'action
        
        Args:
            message: Message à afficher
        """
        formatted = f"{Fore.MAGENTA}[>] {message}{Style.RESET_ALL}"
        print(formatted)
        logger.info(f"Action: {message}")
    
    def status(self, message: str, temp: bool = True):
        """
        Affiche un message de statut (temporaire ou permanent)
        
        Args:
            message: Message à afficher
            temp: Si True, le message est temporaire et sera écrasé par le prochain
        """
        if temp:
            # Effacer la ligne précédente
            sys.stdout.write("\r" + " " * len(self.last_status) + "\r")
            sys.stdout.write(f"{Fore.WHITE}{message}{Style.RESET_ALL}")
            sys.stdout.flush()
            self.last_status = message
        else:
            sys.stdout.write("\r" + " " * len(self.last_status) + "\r")
            sys.stdout.write(f"{Fore.WHITE}{message}{Style.RESET_ALL}\n")
            sys.stdout.flush()
            self.last_status = ""
    
    def progress(self, current: int, total: int, prefix: str = "", suffix: str = "", 
                length: int = 50, fill: str = "█"):
        """
        Affiche une barre de progression
        
        Args:
            current: Valeur actuelle
            total: Valeur totale
            prefix: Préfixe à afficher
            suffix: Suffixe à afficher
            length: Longueur de la barre
            fill: Caractère de remplissage
        """
        percent = ("{0:.1f}").format(100 * (current / float(total)))
        filled_length = int(length * current // total)
        bar = fill * filled_length + "-" * (length - filled_length)
        
        sys.stdout.write(f"\r{prefix} |{bar}| {percent}% {suffix}")
        sys.stdout.flush()
        
        if current == total:
            sys.stdout.write("\n")
    
    def clear(self):
        """Efface l'écran"""
        if sys.platform == "win32":
            import os
            os.system("cls")
        else:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
    
    def prompt(self, message: str, default: Optional[str] = None) -> str:
        """
        Demande une entrée à l'utilisateur
        
        Args:
            message: Message à afficher
            default: Valeur par défaut
            
        Returns:
            Entrée de l'utilisateur
        """
        if default:
            prompt_text = f"{Fore.YELLOW}{message} [{default}]: {Style.RESET_ALL}"
        else:
            prompt_text = f"{Fore.YELLOW}{message}: {Style.RESET_ALL}"
        
        user_input = input(prompt_text)
        
        if not user_input and default:
            return default
        
        return user_input

    def prompt_yes_no(self, message: str, default: bool = True) -> bool:
        """
        Demande une confirmation oui/non à l'utilisateur.
        
        Args:
            message: Message à afficher
            default: Valeur par défaut si l'utilisateur appuie Entrée
        Returns:
            bool: True pour Oui, False pour Non
        """
        default_str = "O/n" if default else "o/N"
        while True:
            resp = input(f"{Fore.YELLOW}{message} [{default_str}]: {Style.RESET_ALL}").strip().lower()
            if not resp:
                return default
            if resp in ("o", "oui", "y", "yes"):
                return True
            if resp in ("n", "non", "no"):
                return False
            print(f"{Fore.YELLOW}Veuillez répondre par o/oui ou n/non.{Style.RESET_ALL}")
    
    def display_target_info(self, target_info: dict):
        """
        Affiche les informations sur une cible
        
        Args:
            target_info: Informations sur la cible
        """
        print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Target Information':^50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}IP:{Style.RESET_ALL} {target_info.get('ip', 'N/A')}")
        print(f"{Fore.WHITE}Hostname:{Style.RESET_ALL} {target_info.get('hostname', 'N/A')}")
        print(f"{Fore.WHITE}Domain:{Style.RESET_ALL} {target_info.get('domain', 'N/A')}")
        print(f"{Fore.WHITE}First Seen:{Style.RESET_ALL} {target_info.get('first_seen', 'N/A')}")
        print(f"{Fore.WHITE}Last Seen:{Style.RESET_ALL} {target_info.get('last_seen', 'N/A')}")
        
        print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")
    
    def display_ports(self, ports: list):
        """
        Affiche les ports ouverts d'une cible
        
        Args:
            ports: Liste des ports ouverts
        """
        print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Open Ports':^50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}{'Port':<10}{'Protocol':<10}{'Service':<15}{'Version':<15}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")
        
        for port in ports:
            print(f"{port['port_number']:<10}{port['protocol']:<10}{port['service']:<15}{port['version']:<15}")
        
        print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")
    
    def display_vulnerabilities(self, vulnerabilities: list):
        """
        Affiche les vulnérabilités d'une cible
        
        Args:
            vulnerabilities: Liste des vulnérabilités
        """
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Vulnerabilities':^70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        
        for vuln in vulnerabilities:
            severity_color = Fore.GREEN
            if vuln['severity'].lower() == 'medium':
                severity_color = Fore.YELLOW
            elif vuln['severity'].lower() in ['high', 'critical']:
                severity_color = Fore.RED
            
            print(f"{Fore.WHITE}Name:{Style.RESET_ALL} {vuln['name']}")
            print(f"{Fore.WHITE}Severity:{Style.RESET_ALL} {severity_color}{vuln['severity']}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}CVE:{Style.RESET_ALL} {vuln['cve'] or 'N/A'}")
            print(f"{Fore.WHITE}Exploited:{Style.RESET_ALL} {'Yes' if vuln['exploited'] else 'No'}")
            print(f"{Fore.WHITE}Description:{Style.RESET_ALL} {vuln['description']}")
            print(f"{Fore.CYAN}{'-' * 70}{Style.RESET_ALL}")
    
    def display_action_history(self, actions: list):
        """
        Affiche l'historique des actions
        
        Args:
            actions: Liste des actions
        """
        print(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Action History':^70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        
        for action in actions:
            status_color = Fore.GREEN if action['success'] else Fore.RED
            status = "Success" if action['success'] else "Failed"
            
            print(f"{Fore.WHITE}Type:{Style.RESET_ALL} {action['action_type']}")
            print(f"{Fore.WHITE}Command:{Style.RESET_ALL} {action['command']}")
            print(f"{Fore.WHITE}Status:{Style.RESET_ALL} {status_color}{status}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Timestamp:{Style.RESET_ALL} {action['timestamp']}")
            print(f"{Fore.CYAN}{'-' * 70}{Style.RESET_ALL}")
    
    def display_dashboard(self, target_info: dict, ports: list, vulnerabilities: list, actions: list):
        """
        Affiche un tableau de bord complet
        
        Args:
            target_info: Informations sur la cible
            ports: Liste des ports ouverts
            vulnerabilities: Liste des vulnérabilités
            actions: Liste des actions
        """
        self.clear()
        
        print(f"{Fore.RED}╔══════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.RED}║{Style.RESET_ALL}          {Fore.CYAN}CTF_mimi ai{Style.RESET_ALL}                    {Fore.RED}║{Style.RESET_ALL}")
        print(f"{Fore.RED}║{Style.RESET_ALL}    {Fore.YELLOW}Agent Autonome de Pentesting{Style.RESET_ALL}        {Fore.RED}║{Style.RESET_ALL}")
        print(f"{Fore.RED}╚══════════════════════════════════════════╝{Style.RESET_ALL}")
        
        self.display_target_info(target_info)
        self.display_ports(ports)
        self.display_vulnerabilities(vulnerabilities)
        self.display_action_history(actions)