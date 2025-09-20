#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Agent - Module principal pour l'agent CTF autonome
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Any
from enum import Enum

from .shell_controller import ShellController
from .toolbox import Toolbox
from .memory import Memory
from .ui import TerminalUI
from .llm_interface import LLMInterface

logger = logging.getLogger("CTF-MIMI-AI.Agent")

class AgentState(Enum):
    """États possibles de l'agent"""
    IDLE = "idle"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    ERROR = "error"

class Agent:
    """
    Classe principale pour l'agent CTF autonome
    """
    
    def __init__(self, shell: ShellController, toolbox: Toolbox, 
                memory: Memory, llm: LLMInterface, ui: TerminalUI):
        """
        Initialise l'agent
        
        Args:
            shell: Contrôleur de shell
            toolbox: Boîte à outils
            memory: Mémoire
            llm: Interface LLM
            ui: Interface utilisateur
        """
        self.shell = shell
        self.toolbox = toolbox
        self.memory = memory
        self.llm = llm
        self.ui = ui
        
        self.state = AgentState.IDLE
        self.target = None
        self.mode = "full"
        self.verbose = False
        self.running = False
        self.thinking = False
        
        # Historique des actions et observations
        self.action_history = []
        self.observation_history = []
        
        # Contexte actuel
        self.context = {
            "target": None,
            "ports": [],
            "vulnerabilities": [],
            "credentials": [],
            "files": [],
            "notes": []
        }
    
    def set_target(self, target: str):
        """
        Définit la cible de l'agent
        
        Args:
            target: Cible (IP, domaine, URL)
        """
        self.target = target
        self.context["target"] = target
        self.ui.info(f"Cible définie: {target}")
    
    def set_mode(self, mode: str):
        """
        Définit le mode d'opération de l'agent
        
        Args:
            mode: Mode d'opération (recon, exploit, post, full)
        """
        self.mode = mode
        self.ui.info(f"Mode d'opération défini: {mode}")
    
    def set_verbose(self, verbose: bool):
        """
        Définit le mode verbeux
        
        Args:
            verbose: Mode verbeux
        """
        self.verbose = verbose
        if verbose:
            self.ui.info("Mode verbeux activé")
    
    def start(self):
        """Démarre l'agent"""
        if not self.target:
            self.ui.error("Aucune cible définie")
            return
        
        self.running = True
        self.ui.info(f"Démarrage de l'agent CTF sur la cible: {self.target}")
        
        # Ajouter la cible à la mémoire
        target_id = self.memory.add_target(self.target)
        
        # Démarrer la boucle autonome
        try:
            self._autonomous_loop(target_id)
        except KeyboardInterrupt:
            self.ui.warning("Arrêt de l'agent demandé par l'utilisateur")
            self.running = False
        except Exception as e:
            self.ui.error(f"Erreur dans la boucle autonome: {str(e)}")
            logger.error(f"Erreur dans la boucle autonome: {str(e)}")
            self.running = False
    
    def stop(self):
        """Arrête l'agent"""
        self.running = False
        self.ui.info("Arrêt de l'agent CTF")
    
    def _autonomous_loop(self, target_id: int):
        """
        Boucle autonome de l'agent
        
        Args:
            target_id: ID de la cible dans la mémoire
        """
        # Vérifier les outils disponibles
        self.ui.thinking("Vérification des outils disponibles...")
        tool_status = self.toolbox.get_tool_status()
        missing_tools = [tool for tool, installed in tool_status.items() if not installed]
        
        if missing_tools:
            self.ui.warning(f"Outils manquants: {', '.join(missing_tools)}")
            self.ui.thinking("Installation des outils manquants...")
            self.toolbox.install_missing_tools()
        
        # Boucle principale
        while self.running:
            # 1. Observer l'état actuel
            self.ui.thinking("Analyse de la situation actuelle...")
            current_state = self._observe(target_id)
            
            # 2. Décider de la prochaine action
            self.ui.thinking("Décision de la prochaine action...")
            next_action = self._decide(current_state)
            
            # 3. Exécuter l'action
            self.ui.action(f"Exécution de l'action: {next_action['description']}")
            result = self._execute(next_action, target_id)
            
            # 4. Mettre à jour la mémoire
            self._update_memory(next_action, result, target_id)
            
            # 5. Afficher les résultats
            if result["success"]:
                self.ui.success(f"Action réussie: {next_action['description']}")
            else:
                self.ui.error(f"Action échouée: {next_action['description']}")
                self.ui.error(f"Erreur: {result.get('error', 'Inconnue')}")
            
            # Pause pour éviter de surcharger le système
            time.sleep(1)
    
    def _observe(self, target_id: int) -> Dict:
        """
        Observe l'état actuel
        
        Args:
            target_id: ID de la cible
            
        Returns:
            État actuel
        """
        # Récupérer les informations de la cible
        target_info = self.memory.get_target_info(target_id)
        ports = self.memory.get_target_ports(target_id)
        vulnerabilities = self.memory.get_target_vulnerabilities(target_id)
        action_history = self.memory.get_action_history(target_id, limit=10)
        
        # Mettre à jour le contexte
        self.context["ports"] = ports
        self.context["vulnerabilities"] = vulnerabilities
        
        # Déterminer l'état actuel
        if not ports:
            current_state = AgentState.RECONNAISSANCE
        elif not vulnerabilities:
            current_state = AgentState.SCANNING
        elif any(not v["exploited"] for v in vulnerabilities):
            current_state = AgentState.EXPLOITATION
        else:
            current_state = AgentState.POST_EXPLOITATION
        
        self.state = current_state
        
        return {
            "target": target_info,
            "ports": ports,
            "vulnerabilities": vulnerabilities,
            "action_history": action_history,
            "state": current_state
        }
    
    def _decide(self, current_state: Dict) -> Dict:
        """
        Décide de la prochaine action à effectuer
        
        Args:
            current_state: État actuel
            
        Returns:
            Prochaine action à effectuer
        """
        # Si nous avons un LLM, lui demander la prochaine action
        if self.llm.is_available():
            return self._decide_with_llm(current_state)
        
        # Sinon, utiliser une logique prédéfinie
        state = current_state["state"]
        
        if state == AgentState.RECONNAISSANCE:
            return {
                "type": "scan",
                "tool": "nmap",
                "params": {
                    "target": self.target,
                    "scan_type": "basic"
                },
                "description": f"Scan de reconnaissance sur {self.target}"
            }
        
        elif state == AgentState.SCANNING:
            # Si nous avons des ports HTTP/HTTPS ouverts, scanner le site web
            http_ports = [p for p in current_state["ports"] 
                         if p["service"] and "http" in p["service"].lower()]
            
            if http_ports:
                port = http_ports[0]["port_number"]
                protocol = "https" if "https" in http_ports[0]["service"].lower() else "http"
                url = f"{protocol}://{self.target}:{port}"
                
                return {
                    "type": "web_scan",
                    "tool": "nikto",
                    "params": {
                        "url": url
                    },
                    "description": f"Scan de vulnérabilités web sur {url}"
                }
            
            # Sinon, scanner tous les ports pour les vulnérabilités
            return {
                "type": "scan",
                "tool": "nmap",
                "params": {
                    "target": self.target,
                    "scan_type": "vuln"
                },
                "description": f"Scan de vulnérabilités sur {self.target}"
            }
        
        elif state == AgentState.EXPLOITATION:
            # Trouver une vulnérabilité non exploitée
            vuln = next((v for v in current_state["vulnerabilities"] if not v["exploited"]), None)
            
            if vuln:
                return {
                    "type": "exploit",
                    "tool": "metasploit",
                    "params": {
                        "exploit": f"exploit/multi/misc/generic",  # À remplacer par un exploit réel
                        "options": {
                            "RHOSTS": self.target
                        }
                    },
                    "vulnerability_id": vuln["id"],
                    "description": f"Exploitation de la vulnérabilité {vuln['name']}"
                }
            
            # Si pas de vulnérabilité, essayer une attaque par force brute sur SSH
            ssh_port = next((p for p in current_state["ports"] 
                           if p["service"] and "ssh" in p["service"].lower()), None)
            
            if ssh_port:
                return {
                    "type": "brute_force",
                    "tool": "hydra",
                    "params": {
                        "target": self.target,
                        "service": "ssh",
                        "username": "root"
                    },
                    "description": f"Attaque par force brute SSH sur {self.target}"
                }
            
            # Sinon, revenir à la phase de scan
            return {
                "type": "scan",
                "tool": "nmap",
                "params": {
                    "target": self.target,
                    "scan_type": "full"
                },
                "description": f"Scan complet sur {self.target}"
            }
        
        elif state == AgentState.POST_EXPLOITATION:
            return {
                "type": "post",
                "tool": "shell",
                "params": {
                    "command": "id && hostname && ifconfig"
                },
                "description": "Collecte d'informations post-exploitation"
            }
        
        else:
            return {
                "type": "scan",
                "tool": "nmap",
                "params": {
                    "target": self.target,
                    "scan_type": "basic"
                },
                "description": f"Scan de base sur {self.target}"
            }
    
    def _decide_with_llm(self, current_state: Dict) -> Dict:
        """
        Utilise le LLM pour décider de la prochaine action
        
        Args:
            current_state: État actuel
            
        Returns:
            Prochaine action à effectuer
        """
        self.thinking = True
        
        # Préparer le contexte pour le LLM
        prompt = self._prepare_llm_prompt(current_state)
        
        # Obtenir la décision du LLM
        self.ui.thinking("Consultation du LLM pour la prochaine action...")
        response = self.llm.generate(prompt)
        
        # Analyser la réponse du LLM
        try:
            action = self._parse_llm_response(response)
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de la réponse du LLM: {str(e)}")
            # Action par défaut en cas d'erreur
            action = {
                "type": "scan",
                "tool": "nmap",
                "params": {
                    "target": self.target,
                    "scan_type": "basic"
                },
                "description": f"Scan de base sur {self.target} (action par défaut)"
            }
        
        self.thinking = False
        return action
    
    def _prepare_llm_prompt(self, current_state: Dict) -> str:
        """
        Prépare le prompt pour le LLM
        
        Args:
            current_state: État actuel
            
        Returns:
            Prompt pour le LLM
        """
        # Construire un prompt détaillé avec le contexte actuel
        target_info = current_state["target"]
        ports = current_state["ports"]
        vulnerabilities = current_state["vulnerabilities"]
        action_history = current_state["action_history"]
        
        prompt = f"""
        Tu es un agent CTF autonome qui doit décider de la prochaine action à effectuer.
        
        CIBLE:
        - IP: {target_info.get('ip')}
        - Hostname: {target_info.get('hostname')}
        - Domain: {target_info.get('domain')}
        
        PORTS OUVERTS:
        """
        
        for port in ports:
            prompt += f"- {port['port_number']}/{port['protocol']}: {port['service']} {port['version'] or ''}\n"
        
        prompt += "\nVULNÉRABILITÉS DÉTECTÉES:\n"
        
        for vuln in vulnerabilities:
            prompt += f"- {vuln['name']} ({vuln['severity']}): {vuln['description']}\n"
            prompt += f"  CVE: {vuln['cve'] or 'N/A'}, Exploitée: {'Oui' if vuln['exploited'] else 'Non'}\n"
        
        prompt += "\nDERNIÈRES ACTIONS:\n"
        
        for action in action_history:
            prompt += f"- {action['action_type']}: {action['command']}\n"
            prompt += f"  Résultat: {'Succès' if action['success'] else 'Échec'}\n"
        
        prompt += """
        DÉCIDE DE LA PROCHAINE ACTION À EFFECTUER.
        
        Format de réponse:
        {
            "type": "scan|web_scan|exploit|brute_force|post",
            "tool": "nom_de_l_outil",
            "params": {
                "param1": "valeur1",
                "param2": "valeur2"
            },
            "description": "Description de l'action"
        }
        """
        
        return prompt
    
    def _parse_llm_response(self, response: str) -> Dict:
        """
        Analyse la réponse du LLM
        
        Args:
            response: Réponse du LLM
            
        Returns:
            Action à effectuer
        """
        import json
        import re
        
        # Extraire le JSON de la réponse
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        
        if not json_match:
            raise ValueError("Aucun JSON trouvé dans la réponse du LLM")
        
        json_str = json_match.group(0)
        
        try:
            action = json.loads(json_str)
            
            # Vérifier que l'action contient les champs requis
            required_fields = ["type", "tool", "params", "description"]
            for field in required_fields:
                if field not in action:
                    raise ValueError(f"Champ requis manquant dans l'action: {field}")
            
            return action
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Erreur lors du décodage JSON: {str(e)}")
    
    def _execute(self, action: Dict, target_id: int) -> Dict:
        """
        Exécute une action
        
        Args:
            action: Action à exécuter
            target_id: ID de la cible
            
        Returns:
            Résultat de l'action
        """
        action_type = action["type"]
        tool = action["tool"]
        params = action["params"]
        
        result = {"success": False, "output": "", "error": ""}
        
        try:
            if action_type == "scan":
                if tool == "nmap":
                    result = self.toolbox.scan_target(
                        params["target"], 
                        params.get("scan_type", "basic")
                    )
                    
                    # Analyser les résultats pour extraire les ports et services
                    if result["success"]:
                        self._parse_nmap_results(result["stdout"], target_id)
                
            elif action_type == "web_scan":
                if tool == "nikto":
                    result = self.toolbox.scan_web_vulnerabilities(params["url"])
                elif tool == "gobuster":
                    result = self.toolbox.discover_directories(
                        params["url"], 
                        params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
                    )
                elif tool == "wpscan":
                    result = self.toolbox.scan_wordpress(params["url"])
            
            elif action_type == "exploit":
                if tool == "metasploit":
                    result = self.toolbox.metasploit_exploit(
                        params["exploit"],
                        params["options"]
                    )
                    
                    # Marquer la vulnérabilité comme exploitée si l'action réussit
                    if result["success"] and "vulnerability_id" in action:
                        self._mark_vulnerability_exploited(action["vulnerability_id"])
                
            elif action_type == "brute_force":
                if tool == "hydra":
                    result = self.toolbox.brute_force(
                        params["target"],
                        params["service"],
                        params["username"],
                        params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
                    )
            
            elif action_type == "post":
                if tool == "shell":
                    result = self.shell.execute(params["command"])
            
            else:
                result["error"] = f"Type d'action non pris en charge: {action_type}"
                
            # Ajouter l'action à l'historique
            self.action_history.append({
                "type": action_type,
                "tool": tool,
                "params": params,
                "result": result,
                "timestamp": time.time()
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'action: {str(e)}")
            result["error"] = str(e)
            return result
    
    def _parse_nmap_results(self, output: str, target_id: int):
        """
        Analyse les résultats de nmap pour extraire les ports et services
        
        Args:
            output: Sortie de nmap
            target_id: ID de la cible
        """
        import re
        
        # Regex pour extraire les ports et services
        port_regex = r'(\d+)\/(\w+)\s+(\w+)\s+(.+)'
        
        for line in output.splitlines():
            match = re.search(port_regex, line)
            if match:
                port_number = int(match.group(1))
                protocol = match.group(2)
                state = match.group(3)
                service_info = match.group(4)
                
                if state.lower() == "open":
                    # Extraire le service et la version
                    service_parts = service_info.split()
                    service = service_parts[0] if service_parts else ""
                    version = " ".join(service_parts[1:]) if len(service_parts) > 1 else ""
                    
                    # Ajouter le port à la mémoire
                    self.memory.add_port(target_id, port_number, protocol, service, version)
    
    def _mark_vulnerability_exploited(self, vulnerability_id: int):
        """
        Marque une vulnérabilité comme exploitée
        
        Args:
            vulnerability_id: ID de la vulnérabilité
        """
        try:
            cursor = self.memory.conn.cursor()
            
            cursor.execute('''
            UPDATE vulnerabilities
            SET exploited = 1
            WHERE id = ?
            ''', (vulnerability_id,))
            
            self.memory.conn.commit()
            
        except Exception as e:
            logger.error(f"Erreur lors du marquage de la vulnérabilité comme exploitée: {str(e)}")
    
    def _update_memory(self, action: Dict, result: Dict, target_id: int):
        """
        Met à jour la mémoire avec les résultats de l'action
        
        Args:
            action: Action exécutée
            result: Résultat de l'action
            target_id: ID de la cible
        """
        # Ajouter l'action à la mémoire
        self.memory.add_action(
            target_id,
            action["type"],
            str(action["params"]),
            result.get("stdout", ""),
            result["success"]
        )
        
        # Mettre à jour la dernière activité de la cible
        try:
            cursor = self.memory.conn.cursor()
            
            cursor.execute('''
            UPDATE targets
            SET last_seen = datetime('now')
            WHERE id = ?
            ''', (target_id,))
            
            self.memory.conn.commit()
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la dernière activité: {str(e)}")