#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'interface LLM pour l'agent CTF autonome.
Permet l'intégration avec différents modèles de langage locaux.
"""

import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional, Union, Tuple

logger = logging.getLogger("CTF-MIMI-AI.LLM")

class LLMInterface:
    """Interface pour communiquer avec différents modèles de langage locaux."""
    
    def __init__(self, model_type: str = "mistral", model_path: Optional[str] = None, 
                 api_url: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialise l'interface LLM.
        
        Args:
            model_type: Type de modèle ('mistral', 'llama', 'falcon', etc.)
            model_path: Chemin vers le modèle local (si applicable)
            api_url: URL de l'API (pour les modèles exposés via API)
            api_key: Clé API (si nécessaire)
        """
        self.model_type = model_type.lower()
        self.model_path = model_path
        self.api_url = api_url
        self.api_key = api_key
        self.model = None
        self.tokenizer = None
        self.initialized = False
        
        # Configuration par défaut pour les différents types de modèles
        self.model_configs = {
            "mistral": {
                "default_api_url": "http://localhost:8000/v1",
                "context_window": 8192,
                "temperature": 0.7,
                "max_tokens": 1024
            },
            "llama": {
                "default_api_url": "http://localhost:8080/completion",
                "context_window": 4096,
                "temperature": 0.7,
                "max_tokens": 1024
            },
            "falcon": {
                "default_api_url": "http://localhost:5000/generate",
                "context_window": 2048,
                "temperature": 0.8,
                "max_tokens": 800
            },
            "gpt-oss": {
                "default_api_url": "http://127.0.0.1:1234/v1",
                "context_window": 8192,
                "temperature": 0.7,
                "max_tokens": 1024
            }
        }
        
        # Utiliser l'URL par défaut si non spécifiée
        if not self.api_url and self.model_type in self.model_configs:
            self.api_url = self.model_configs[self.model_type]["default_api_url"]
    
    def initialize(self) -> bool:
        """
        Initialise la connexion avec le modèle LLM.
        
        Returns:
            bool: True si l'initialisation a réussi, False sinon
        """
        try:
            if self.model_type == "mistral" and self.model_path:
                # Chargement direct du modèle Mistral (nécessite les bibliothèques appropriées)
                try:
                    from transformers import AutoModelForCausalLM, AutoTokenizer
                    logger.info(f"Chargement du modèle Mistral depuis {self.model_path}")
                    self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.model_path, 
                        device_map="auto",
                        load_in_8bit=True  # Optimisation pour les machines avec moins de VRAM
                    )
                    self.initialized = True
                    return True
                except ImportError:
                    logger.warning("Bibliothèques transformers non disponibles, passage en mode API")
            
            # Mode API (pour tous les modèles exposés via API)
            if self.api_url:
                logger.info(f"Initialisation de l'interface LLM en mode API: {self.api_url}")
                # Test de connexion à l'API
                response = self._test_api_connection()
                if response:
                    logger.info("Connexion à l'API LLM réussie")
                    self.initialized = True
                    return True
                else:
                    logger.error(f"Échec de connexion à l'API LLM: {self.api_url}")
            
            logger.error("Échec d'initialisation du LLM: configuration invalide")
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du LLM: {str(e)}")
            return False
    
    def _test_api_connection(self) -> bool:
        """Teste la connexion à l'API LLM."""
        try:
            # Différentes méthodes de test selon le type d'API
            if "v1" in self.api_url:  # API compatible OpenAI
                headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                response = requests.get(
                    self.api_url.replace("/v1", "/v1/models"), 
                    headers=headers,
                    timeout=5
                )
                return response.status_code == 200
            else:  # Autres API personnalisées
                return True  # Supposons que l'API est disponible
        except Exception as e:
            logger.error(f"Erreur lors du test de connexion à l'API: {str(e)}")
            return False
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                 temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> Tuple[bool, str]:
        """
        Génère une réponse à partir du prompt fourni.
        
        Args:
            prompt: Le prompt principal
            system_prompt: Instructions système (pour les modèles qui supportent ce format)
            temperature: Température pour la génération (créativité)
            max_tokens: Nombre maximum de tokens à générer
            
        Returns:
            Tuple[bool, str]: (Succès, Réponse générée)
        """
        if not self.initialized:
            if not self.initialize():
                return False, "LLM non initialisé"
        
        # Utiliser les valeurs par défaut si non spécifiées
        if temperature is None and self.model_type in self.model_configs:
            temperature = self.model_configs[self.model_type]["temperature"]
        if max_tokens is None and self.model_type in self.model_configs:
            max_tokens = self.model_configs[self.model_type]["max_tokens"]
        
        try:
            # Génération directe avec le modèle chargé
            if self.model and self.tokenizer:
                return self._generate_with_model(prompt, system_prompt, temperature, max_tokens)
            
            # Génération via API
            if self.api_url:
                return self._generate_with_api(prompt, system_prompt, temperature, max_tokens)
            
            return False, "Aucune méthode de génération disponible"
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération: {str(e)}")
            return False, f"Erreur: {str(e)}"
    
    def _generate_with_model(self, prompt: str, system_prompt: Optional[str], 
                            temperature: float, max_tokens: int) -> Tuple[bool, str]:
        """Génère une réponse en utilisant le modèle chargé directement."""
        try:
            # Préparation du prompt avec le format approprié
            if system_prompt:
                full_prompt = f"<s>[INST] {system_prompt}\n\n{prompt} [/INST]"
            else:
                full_prompt = f"<s>[INST] {prompt} [/INST]"
            
            # Tokenisation et génération
            inputs = self.tokenizer(full_prompt, return_tensors="pt").to(self.model.device)
            outputs = self.model.generate(
                inputs["input_ids"],
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
            )
            
            # Décodage de la réponse
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Extraction de la partie réponse uniquement (après [/INST])
            if "[/INST]" in response:
                response = response.split("[/INST]")[1].strip()
            
            return True, response
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération avec le modèle: {str(e)}")
            return False, f"Erreur: {str(e)}"
    
    def _generate_with_api(self, prompt: str, system_prompt: Optional[str], 
                          temperature: float, max_tokens: int) -> Tuple[bool, str]:
        """Génère une réponse en utilisant l'API."""
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            # Format de la requête selon le type d'API
            if "v1" in self.api_url:  # API compatible OpenAI
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                
                payload = {
                    "model": self.model_type,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
                
                response = requests.post(
                    f"{self.api_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return True, result["choices"][0]["message"]["content"]
                else:
                    logger.error(f"Erreur API: {response.status_code} - {response.text}")
                    return False, f"Erreur API: {response.status_code}"
                
            else:  # Autres API personnalisées (format générique)
                payload = {
                    "prompt": prompt,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
                
                if system_prompt:
                    payload["system_prompt"] = system_prompt
                
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # Adapter selon le format de réponse de l'API
                    if "text" in result:
                        return True, result["text"]
                    elif "output" in result:
                        return True, result["output"]
                    elif "response" in result:
                        return True, result["response"]
                    else:
                        return True, str(result)
                else:
                    logger.error(f"Erreur API: {response.status_code} - {response.text}")
                    return False, f"Erreur API: {response.status_code}"
                
        except Exception as e:
            logger.error(f"Erreur lors de la génération avec l'API: {str(e)}")
            return False, f"Erreur: {str(e)}"
    
    def create_ctf_prompt(self, observation: str, memory_context: str, 
                         current_target: str, current_state: str) -> str:
        """
        Crée un prompt spécialisé pour les décisions CTF.
        
        Args:
            observation: Résultats des dernières commandes/observations
            memory_context: Contexte extrait de la mémoire (cibles, ports, vulnérabilités)
            current_target: Cible actuelle
            current_state: État actuel de l'agent
            
        Returns:
            str: Prompt formaté pour le LLM
        """
        system_instructions = """
        Tu es un expert en cybersécurité spécialisé dans les CTF (Capture The Flag).
        Ta mission est d'analyser les informations fournies et de décider de la prochaine action à effectuer.
        Tu dois être méthodique, précis et efficace dans tes décisions.
        
        Réponds UNIQUEMENT au format JSON avec la structure suivante:
        {
            "reasoning": "Ton raisonnement détaillé",
            "action": "nom_de_l_action",
            "params": {
                "param1": "valeur1",
                "param2": "valeur2"
            }
        }
        
        Les actions disponibles sont:
        - scan_target: Lancer un scan (params: ip, scan_type)
        - enumerate_web: Énumérer un service web (params: url, tool)
        - bruteforce: Tenter une attaque par force brute (params: service, target, port, wordlist)
        - exploit: Exploiter une vulnérabilité (params: vuln_type, target, port)
        - analyze_results: Analyser des résultats précédents (params: result_type)
        - search_exploit: Rechercher un exploit (params: service, version)
        """
        
        context = f"""
        ## Cible actuelle
        {current_target}
        
        ## État actuel
        {current_state}
        
        ## Contexte de la mémoire
        {memory_context}
        
        ## Dernière observation
        {observation}
        
        Quelle est la prochaine action la plus pertinente à effectuer?
        """
        
        return context, system_instructions
    
    def parse_llm_response(self, response: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Parse la réponse du LLM au format JSON.
        
        Args:
            response: Réponse brute du LLM
            
        Returns:
            Tuple[bool, Dict]: (Succès, Données parsées)
        """
        try:
            # Extraction du JSON si la réponse contient d'autres éléments
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
                
                # Validation des champs requis
                if "action" in data and "params" in data:
                    return True, data
                else:
                    logger.warning(f"Réponse LLM invalide, champs manquants: {data}")
                    return False, {"error": "Champs requis manquants dans la réponse"}
            else:
                logger.warning(f"Aucun JSON trouvé dans la réponse: {response}")
                return False, {"error": "Format de réponse invalide", "raw_response": response}
                
        except json.JSONDecodeError as e:
            logger.error(f"Erreur de décodage JSON: {str(e)}, réponse: {response}")
            return False, {"error": f"Erreur de décodage JSON: {str(e)}", "raw_response": response}
        except Exception as e:
            logger.error(f"Erreur lors du parsing de la réponse LLM: {str(e)}")
            return False, {"error": f"Erreur: {str(e)}", "raw_response": response}


# Exemple d'utilisation:
if __name__ == "__main__":
    # Configuration du logging
    logging.basicConfig(level=logging.INFO)
    
    # Test avec API locale
    llm = LLMInterface(model_type="mistral", api_url="http://localhost:8000/v1")
    
    if llm.initialize():
        success, response = llm.generate(
            prompt="Quelles sont les premières étapes pour analyser une machine dans un CTF?",
            system_prompt="Tu es un expert en cybersécurité spécialisé dans les CTF."
        )
        
        if success:
            print("Réponse du LLM:")
            print(response)
        else:
            print(f"Erreur: {response}")
    else:
        print("Échec d'initialisation du LLM")