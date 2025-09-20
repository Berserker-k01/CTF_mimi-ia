#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shell Controller - Module pour exécuter des commandes shell dans Kali Linux
"""

import os
import subprocess
import shlex
import logging
import time
import pexpect
from typing import Dict, List, Tuple, Optional, Union

logger = logging.getLogger("CTF-MIMI-AI.ShellController")

class ShellController:
    """
    Classe pour exécuter des commandes shell et gérer les interactions avec le terminal
    """
    
    def __init__(self, timeout: int = 60):
        """
        Initialise le contrôleur de shell
        
        Args:
            timeout: Timeout par défaut pour les commandes (en secondes)
        """
        self.timeout = timeout
        self.last_output = ""
        self.last_error = ""
        self.last_return_code = 0
        self.history = []
        
        # Vérifier si nous sommes sur Kali Linux
        self.is_kali = self._check_kali()
        if not self.is_kali:
            logger.warning("Ce système ne semble pas être Kali Linux. Certaines fonctionnalités pourraient ne pas fonctionner.")
    
    def _check_kali(self) -> bool:
        """Vérifie si le système est Kali Linux"""
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                return "kali" in content
        except:
            return False
    
    def execute(self, command: str, capture_output: bool = True, 
                shell: bool = False, timeout: Optional[int] = None) -> Dict:
        """
        Exécute une commande shell et retourne le résultat
        
        Args:
            command: Commande à exécuter
            capture_output: Capturer la sortie standard et d'erreur
            shell: Utiliser un shell pour exécuter la commande
            timeout: Timeout spécifique pour cette commande
            
        Returns:
            Dict contenant stdout, stderr, et le code de retour
        """
        if timeout is None:
            timeout = self.timeout
            
        start_time = time.time()
        logger.debug(f"Exécution de la commande: {command}")
        
        try:
            if shell:
                process = subprocess.run(
                    command,
                    shell=True,
                    capture_output=capture_output,
                    text=True,
                    timeout=timeout
                )
            else:
                args = shlex.split(command)
                process = subprocess.run(
                    args,
                    shell=False,
                    capture_output=capture_output,
                    text=True,
                    timeout=timeout
                )
                
            self.last_output = process.stdout
            self.last_error = process.stderr
            self.last_return_code = process.returncode
            
            execution_time = time.time() - start_time
            
            result = {
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "command": command,
                "execution_time": execution_time,
                "success": process.returncode == 0
            }
            
            self.history.append(result)
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout expiré pour la commande: {command}")
            result = {
                "stdout": "",
                "stderr": "Timeout expiré",
                "returncode": -1,
                "command": command,
                "execution_time": time.time() - start_time,
                "success": False
            }
            self.history.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande {command}: {str(e)}")
            result = {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "command": command,
                "execution_time": time.time() - start_time,
                "success": False
            }
            self.history.append(result)
            return result
    
    def execute_interactive(self, command: str, 
                           expect_patterns: List[str] = None,
                           responses: List[str] = None,
                           timeout: Optional[int] = None) -> Dict:
        """
        Exécute une commande interactive qui nécessite des entrées utilisateur
        
        Args:
            command: Commande à exécuter
            expect_patterns: Motifs à attendre (prompts)
            responses: Réponses à envoyer pour chaque motif
            timeout: Timeout spécifique pour cette commande
            
        Returns:
            Dict contenant la sortie et le statut
        """
        if timeout is None:
            timeout = self.timeout
            
        if expect_patterns is None or responses is None:
            expect_patterns = []
            responses = []
            
        if len(expect_patterns) != len(responses):
            raise ValueError("Le nombre de motifs et de réponses doit être identique")
            
        logger.debug(f"Exécution de la commande interactive: {command}")
        
        try:
            child = pexpect.spawn(command, encoding='utf-8', timeout=timeout)
            output = []
            
            for pattern, response in zip(expect_patterns, responses):
                index = child.expect([pattern, pexpect.EOF, pexpect.TIMEOUT])
                output.append(child.before + child.after)
                
                if index == 0:  # Motif trouvé
                    child.sendline(response)
                elif index == 1:  # EOF
                    break
                elif index == 2:  # TIMEOUT
                    logger.warning(f"Timeout en attendant le motif: {pattern}")
                    break
            
            # Attendre la fin du processus
            child.expect([pexpect.EOF, pexpect.TIMEOUT])
            output.append(child.before)
            
            child.close()
            returncode = child.exitstatus
            
            result = {
                "stdout": "".join(output),
                "returncode": returncode,
                "command": command,
                "success": returncode == 0
            }
            
            self.history.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande interactive {command}: {str(e)}")
            result = {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "command": command,
                "success": False
            }
            self.history.append(result)
            return result
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """
        Vérifie si un outil est installé sur le système
        
        Args:
            tool_name: Nom de l'outil à vérifier
            
        Returns:
            True si l'outil est installé, False sinon
        """
        result = self.execute(f"which {tool_name}")
        return result["success"]
    
    def install_tool(self, tool_name: str, method: str = "apt") -> bool:
        """
        Installe un outil sur le système
        
        Args:
            tool_name: Nom de l'outil à installer
            method: Méthode d'installation (apt, pip, git)
            
        Returns:
            True si l'installation a réussi, False sinon
        """
        if method == "apt":
            result = self.execute(f"apt-get update && apt-get install -y {tool_name}")
        elif method == "pip":
            result = self.execute(f"pip install {tool_name}")
        elif method == "git":
            # Supposons que tool_name est une URL git
            repo_name = tool_name.split("/")[-1].replace(".git", "")
            result = self.execute(f"git clone {tool_name} /opt/{repo_name}")
        else:
            logger.error(f"Méthode d'installation non prise en charge: {method}")
            return False
            
        return result["success"]
    
    def get_history(self, limit: int = 10) -> List[Dict]:
        """
        Retourne l'historique des commandes exécutées
        
        Args:
            limit: Nombre maximum de commandes à retourner
            
        Returns:
            Liste des dernières commandes exécutées
        """
        return self.history[-limit:]