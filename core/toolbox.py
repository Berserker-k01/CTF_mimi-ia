#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Toolbox - Interface pour les outils de sécurité de Kali Linux
"""

import logging
from typing import Dict, List, Optional, Any
from .shell_controller import ShellController

logger = logging.getLogger("CTF-MIMI-AI.Toolbox")

class Toolbox:
    """
    Interface pour les outils de sécurité de Kali Linux
    """
    
    def __init__(self, shell: ShellController):
        """
        Initialise la boîte à outils
        
        Args:
            shell: Contrôleur de shell pour exécuter les commandes
        """
        self.shell = shell
        self.tools = {
            "nmap": self.is_installed("nmap"),
            "gobuster": self.is_installed("gobuster"),
            "sqlmap": self.is_installed("sqlmap"),
            "metasploit": self.is_installed("msfconsole"),
            "hydra": self.is_installed("hydra"),
            "nikto": self.is_installed("nikto"),
            "dirb": self.is_installed("dirb"),
            "wpscan": self.is_installed("wpscan"),
            "john": self.is_installed("john"),
            "hashcat": self.is_installed("hashcat")
        }
    
    def is_installed(self, tool_name: str) -> bool:
        """
        Vérifie si un outil est installé
        
        Args:
            tool_name: Nom de l'outil à vérifier
            
        Returns:
            True si l'outil est installé, False sinon
        """
        return self.shell.check_tool_installed(tool_name)
    
    def install_missing_tools(self) -> Dict[str, bool]:
        """
        Installe les outils manquants
        
        Returns:
            Dictionnaire avec les résultats d'installation
        """
        results = {}
        for tool, installed in self.tools.items():
            if not installed:
                logger.info(f"Installation de l'outil manquant: {tool}")
                success = self.shell.install_tool(tool)
                results[tool] = success
                if success:
                    self.tools[tool] = True
        return results
    
    # === RECONNAISSANCE ===
    
    def scan_target(self, target: str, scan_type: str = "basic") -> Dict:
        """
        Scanne une cible avec nmap
        
        Args:
            target: Cible à scanner (IP, domaine)
            scan_type: Type de scan (basic, full, vuln, quick)
            
        Returns:
            Résultat du scan
        """
        if not self.tools["nmap"]:
            logger.warning("nmap n'est pas installé")
            return {"success": False, "error": "nmap n'est pas installé"}
        
        if scan_type == "basic":
            cmd = f"nmap -sV -sC {target}"
        elif scan_type == "full":
            cmd = f"nmap -sV -sC -p- -A {target}"
        elif scan_type == "vuln":
            cmd = f"nmap -sV --script vuln {target}"
        elif scan_type == "quick":
            cmd = f"nmap -T4 -F {target}"
        else:
            cmd = f"nmap {target}"
        
        return self.shell.execute(cmd)
    
    def discover_directories(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict:
        """
        Découvre les répertoires d'un site web avec gobuster ou dirb
        
        Args:
            url: URL à scanner
            wordlist: Chemin vers la wordlist à utiliser
            
        Returns:
            Résultat de la découverte
        """
        if self.tools["gobuster"]:
            cmd = f"gobuster dir -u {url} -w {wordlist} -q"
            return self.shell.execute(cmd)
        elif self.tools["dirb"]:
            cmd = f"dirb {url} {wordlist} -o dirb_results.txt"
            return self.shell.execute(cmd)
        else:
            logger.warning("gobuster et dirb ne sont pas installés")
            return {"success": False, "error": "gobuster et dirb ne sont pas installés"}
    
    def scan_web_vulnerabilities(self, url: str) -> Dict:
        """
        Scanne les vulnérabilités d'un site web avec nikto
        
        Args:
            url: URL à scanner
            
        Returns:
            Résultat du scan
        """
        if not self.tools["nikto"]:
            logger.warning("nikto n'est pas installé")
            return {"success": False, "error": "nikto n'est pas installé"}
        
        cmd = f"nikto -h {url}"
        return self.shell.execute(cmd)
    
    def scan_wordpress(self, url: str) -> Dict:
        """
        Scanne un site WordPress avec wpscan
        
        Args:
            url: URL du site WordPress
            
        Returns:
            Résultat du scan
        """
        if not self.tools["wpscan"]:
            logger.warning("wpscan n'est pas installé")
            return {"success": False, "error": "wpscan n'est pas installé"}
        
        cmd = f"wpscan --url {url} --enumerate u,p,t"
        return self.shell.execute(cmd)
    
    # === EXPLOITATION ===
    
    def sql_injection(self, url: str, data: Optional[str] = None) -> Dict:
        """
        Teste les injections SQL avec sqlmap
        
        Args:
            url: URL à tester
            data: Données POST (optionnel)
            
        Returns:
            Résultat du test
        """
        if not self.tools["sqlmap"]:
            logger.warning("sqlmap n'est pas installé")
            return {"success": False, "error": "sqlmap n'est pas installé"}
        
        if data:
            cmd = f"sqlmap -u {url} --data=\"{data}\" --batch"
        else:
            cmd = f"sqlmap -u {url} --batch"
        
        return self.shell.execute(cmd)
    
    def brute_force(self, target: str, service: str, username: str, 
                   wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict:
        """
        Effectue une attaque par force brute avec hydra
        
        Args:
            target: Cible (IP, domaine)
            service: Service à attaquer (ssh, ftp, http-post-form, etc.)
            username: Nom d'utilisateur
            wordlist: Chemin vers la wordlist à utiliser
            
        Returns:
            Résultat de l'attaque
        """
        if not self.tools["hydra"]:
            logger.warning("hydra n'est pas installé")
            return {"success": False, "error": "hydra n'est pas installé"}
        
        cmd = f"hydra -l {username} -P {wordlist} {target} {service}"
        return self.shell.execute(cmd)
    
    def metasploit_exploit(self, exploit: str, options: Dict[str, str]) -> Dict:
        """
        Exécute un exploit Metasploit
        
        Args:
            exploit: Chemin de l'exploit (ex: exploit/multi/http/apache_struts2_rest_xstream)
            options: Options de l'exploit (ex: {"RHOSTS": "192.168.1.1", "LHOST": "192.168.1.2"})
            
        Returns:
            Résultat de l'exploitation
        """
        if not self.tools["metasploit"]:
            logger.warning("metasploit n'est pas installé")
            return {"success": False, "error": "metasploit n'est pas installé"}
        
        # Créer un script RC pour Metasploit
        with open("exploit.rc", "w") as f:
            f.write(f"use {exploit}\n")
            for key, value in options.items():
                f.write(f"set {key} {value}\n")
            f.write("exploit -j\n")
        
        cmd = "msfconsole -q -r exploit.rc"
        return self.shell.execute(cmd)
    
    # === POST-EXPLOITATION ===
    
    def crack_hash(self, hash_file: str, hash_type: str = "auto", 
                  wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict:
        """
        Craque un hash avec John the Ripper ou hashcat
        
        Args:
            hash_file: Chemin vers le fichier contenant le hash
            hash_type: Type de hash (auto, md5, sha1, etc.)
            wordlist: Chemin vers la wordlist à utiliser
            
        Returns:
            Résultat du craquage
        """
        if self.tools["john"]:
            if hash_type == "auto":
                cmd = f"john --wordlist={wordlist} {hash_file}"
            else:
                cmd = f"john --format={hash_type} --wordlist={wordlist} {hash_file}"
            return self.shell.execute(cmd)
        elif self.tools["hashcat"]:
            if hash_type == "auto":
                logger.warning("hashcat nécessite un type de hash spécifique")
                return {"success": False, "error": "hashcat nécessite un type de hash spécifique"}
            cmd = f"hashcat -m {hash_type} -a 0 {hash_file} {wordlist}"
            return self.shell.execute(cmd)
        else:
            logger.warning("john et hashcat ne sont pas installés")
            return {"success": False, "error": "john et hashcat ne sont pas installés"}
    
    # === UTILITAIRES ===
    
    def get_tool_status(self) -> Dict[str, bool]:
        """
        Retourne l'état des outils
        
        Returns:
            Dictionnaire avec l'état des outils
        """
        return self.tools