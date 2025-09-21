#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Memory - Module pour stocker et gérer les informations collectées
"""

import os
import json
import sqlite3
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger("CTF-MIMI-AI.Memory")

class Memory:
    """
    Classe pour stocker et gérer les informations collectées
    """
    
    def __init__(self, db_path: str = "ctf_mimi_ai_memory.db"):
        """
        Initialise la mémoire
        
        Args:
            db_path: Chemin vers la base de données SQLite
        """
        self.db_path = db_path
        self.conn = None
        self.init_db()
        
        # Cache pour les données fréquemment utilisées
        self.cache = {}
        
        # Historique des actions
        self.action_history = []
        
        # Informations sur la cible actuelle
        self.current_target = None
        self.target_info = {}
        
    def init_db(self):
        """Initialise la base de données SQLite"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # Table pour les cibles
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                domain TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                notes TEXT
            )
            ''')
            
            # Table pour les ports ouverts
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                port_number INTEGER,
                protocol TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            ''')
            
            # Table pour les vulnérabilités
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                port_id INTEGER,
                name TEXT,
                description TEXT,
                severity TEXT,
                cve TEXT,
                discovered_at TIMESTAMP,
                exploited BOOLEAN,
                notes TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id),
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
            ''')
            
            # Table pour les actions
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                action_type TEXT,
                command TEXT,
                result TEXT,
                timestamp TIMESTAMP,
                success BOOLEAN,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            ''')
            
            # Table pour les credentials
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                username TEXT,
                password TEXT,
                service TEXT,
                port INTEGER,
                discovered_at TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
            ''')
            
            self.conn.commit()
            logger.info("Base de données initialisée avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la base de données: {str(e)}")
    
    def add_target(self, ip: str, hostname: Optional[str] = None, 
                  domain: Optional[str] = None) -> int:
        """
        Ajoute une nouvelle cible à la base de données
        
        Args:
            ip: Adresse IP de la cible
            hostname: Nom d'hôte de la cible (optionnel)
            domain: Domaine de la cible (optionnel)
            
        Returns:
            ID de la cible
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()

            # Support des URLs comme cibles
            ip_val = ip
            hostname_val = hostname
            domain_val = domain
            try:
                parsed = urlparse(ip)
                if parsed.scheme in ("http", "https") and parsed.netloc:
                    # Cible est une URL, on stocke host dans hostname/domain, ip non définie
                    ip_val = None
                    if not hostname_val:
                        hostname_val = parsed.netloc
                    if not domain_val:
                        domain_val = parsed.netloc
            except Exception:
                pass

            cursor.execute('''
            INSERT INTO targets (ip, hostname, domain, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ''', (ip_val, hostname_val, domain_val, now, now))

            self.conn.commit()
            target_id = cursor.lastrowid

            self.current_target = target_id
            self.target_info = {
                "id": target_id,
                "ip": ip_val,
                "hostname": hostname_val,
                "domain": domain_val
            }

            display = ip_val or hostname_val or domain_val or ip
            logger.info(f"Nouvelle cible ajoutée: {display}")
            return target_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de la cible: {str(e)}")
            return -1
    
    def add_port(self, target_id: int, port_number: int, protocol: str, 
                service: Optional[str] = None, version: Optional[str] = None) -> int:
        """
        Ajoute un port ouvert à une cible
        
        Args:
            target_id: ID de la cible
            port_number: Numéro du port
            protocol: Protocole (TCP, UDP)
            service: Service détecté (optionnel)
            version: Version du service (optionnel)
            
        Returns:
            ID du port
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            INSERT INTO ports (target_id, port_number, protocol, service, version)
            VALUES (?, ?, ?, ?, ?)
            ''', (target_id, port_number, protocol, service, version))
            
            self.conn.commit()
            port_id = cursor.lastrowid
            
            logger.info(f"Nouveau port ajouté: {port_number}/{protocol} ({service})")
            return port_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout du port: {str(e)}")
            return -1
    
    def add_vulnerability(self, target_id: int, name: str, description: str, 
                         severity: str, port_id: Optional[int] = None, 
                         cve: Optional[str] = None) -> int:
        """
        Ajoute une vulnérabilité à une cible
        
        Args:
            target_id: ID de la cible
            name: Nom de la vulnérabilité
            description: Description de la vulnérabilité
            severity: Sévérité (Low, Medium, High, Critical)
            port_id: ID du port associé (optionnel)
            cve: Identifiant CVE (optionnel)
            
        Returns:
            ID de la vulnérabilité
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO vulnerabilities (target_id, port_id, name, description, severity, cve, discovered_at, exploited)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (target_id, port_id, name, description, severity, cve, now, False))
            
            self.conn.commit()
            vuln_id = cursor.lastrowid
            
            logger.info(f"Nouvelle vulnérabilité ajoutée: {name} ({severity})")
            return vuln_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de la vulnérabilité: {str(e)}")
            return -1
    
    def add_action(self, target_id: int, action_type: str, command: str, 
                  result: str, success: bool) -> int:
        """
        Ajoute une action à l'historique
        
        Args:
            target_id: ID de la cible
            action_type: Type d'action (scan, exploit, etc.)
            command: Commande exécutée
            result: Résultat de la commande
            success: Succès de l'action
            
        Returns:
            ID de l'action
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO actions (target_id, action_type, command, result, timestamp, success)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (target_id, action_type, command, result, now, success))
            
            self.conn.commit()
            action_id = cursor.lastrowid
            
            # Ajouter à l'historique en mémoire
            action = {
                "id": action_id,
                "target_id": target_id,
                "action_type": action_type,
                "command": command,
                "timestamp": now,
                "success": success
            }
            self.action_history.append(action)
            
            logger.debug(f"Nouvelle action ajoutée: {action_type}")
            return action_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de l'action: {str(e)}")
            return -1
    
    def add_credentials(self, target_id: int, username: str, password: str, 
                       service: str, port: Optional[int] = None) -> int:
        """
        Ajoute des credentials à une cible
        
        Args:
            target_id: ID de la cible
            username: Nom d'utilisateur
            password: Mot de passe
            service: Service (ssh, ftp, etc.)
            port: Port du service (optionnel)
            
        Returns:
            ID des credentials
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute('''
            INSERT INTO credentials (target_id, username, password, service, port, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (target_id, username, password, service, port, now))
            
            self.conn.commit()
            cred_id = cursor.lastrowid
            
            logger.info(f"Nouveaux credentials ajoutés: {username}:{password} ({service})")
            return cred_id
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout des credentials: {str(e)}")
            return -1
    
    def get_target_info(self, target_id: int) -> Dict:
        """
        Récupère les informations sur une cible
        
        Args:
            target_id: ID de la cible
            
        Returns:
            Dictionnaire avec les informations sur la cible
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            SELECT id, ip, hostname, domain, first_seen, last_seen, notes
            FROM targets
            WHERE id = ?
            ''', (target_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "ip": row[1],
                    "hostname": row[2],
                    "domain": row[3],
                    "first_seen": row[4],
                    "last_seen": row[5],
                    "notes": row[6]
                }
            else:
                return {}
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations sur la cible: {str(e)}")
            return {}
    
    def get_target_ports(self, target_id: int) -> List[Dict]:
        """
        Récupère les ports ouverts d'une cible
        
        Args:
            target_id: ID de la cible
            
        Returns:
            Liste des ports ouverts
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            SELECT id, port_number, protocol, service, version
            FROM ports
            WHERE target_id = ?
            ''', (target_id,))
            
            ports = []
            for row in cursor.fetchall():
                ports.append({
                    "id": row[0],
                    "port_number": row[1],
                    "protocol": row[2],
                    "service": row[3],
                    "version": row[4]
                })
            
            return ports
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des ports: {str(e)}")
            return []
    
    def get_target_vulnerabilities(self, target_id: int) -> List[Dict]:
        """
        Récupère les vulnérabilités d'une cible
        
        Args:
            target_id: ID de la cible
            
        Returns:
            Liste des vulnérabilités
        """
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
            SELECT id, port_id, name, description, severity, cve, discovered_at, exploited, notes
            FROM vulnerabilities
            WHERE target_id = ?
            ''', (target_id,))
            
            vulns = []
            for row in cursor.fetchall():
                vulns.append({
                    "id": row[0],
                    "port_id": row[1],
                    "name": row[2],
                    "description": row[3],
                    "severity": row[4],
                    "cve": row[5],
                    "discovered_at": row[6],
                    "exploited": bool(row[7]),
                    "notes": row[8]
                })
            
            return vulns
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des vulnérabilités: {str(e)}")
            return []
    
    def get_action_history(self, target_id: Optional[int] = None, limit: int = 20) -> List[Dict]:
        """
        Récupère l'historique des actions
        
        Args:
            target_id: ID de la cible (optionnel)
            limit: Nombre maximum d'actions à récupérer
            
        Returns:
            Liste des actions
        """
        try:
            cursor = self.conn.cursor()
            
            if target_id:
                cursor.execute('''
                SELECT id, action_type, command, result, timestamp, success
                FROM actions
                WHERE target_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                ''', (target_id, limit))
            else:
                cursor.execute('''
                SELECT id, target_id, action_type, command, result, timestamp, success
                FROM actions
                ORDER BY timestamp DESC
                LIMIT ?
                ''', (limit,))
            
            actions = []
            for row in cursor.fetchall():
                if target_id:
                    actions.append({
                        "id": row[0],
                        "action_type": row[1],
                        "command": row[2],
                        "result": row[3],
                        "timestamp": row[4],
                        "success": bool(row[5])
                    })
                else:
                    actions.append({
                        "id": row[0],
                        "target_id": row[1],
                        "action_type": row[2],
                        "command": row[3],
                        "result": row[4],
                        "timestamp": row[5],
                        "success": bool(row[6])
                    })
            
            return actions
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'historique des actions: {str(e)}")
            return []
    
    def close(self):
        """Ferme la connexion à la base de données"""
        if self.conn:
            self.conn.close()
            logger.info("Connexion à la base de données fermée")