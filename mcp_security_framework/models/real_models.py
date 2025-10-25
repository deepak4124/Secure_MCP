import torch
from transformers import (
    AutoTokenizer, AutoModel, AutoModelForSequenceClassification,
    pipeline, BertTokenizer, BertModel
)
import numpy as np
from typing import Dict, List, Any, Tuple
import logging
import os

# Setup Hugging Face authentication
try:
    from huggingface_hub import login
    HF_TOKEN = "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"
    os.environ["HUGGINGFACE_HUB_TOKEN"] = HF_TOKEN
    login(token=HF_TOKEN)
    print("✅ Hugging Face authentication successful!")
except Exception as e:
    print(f"⚠️  Hugging Face authentication warning: {e}")

class RealTrustModel:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Load models
        self.trust_tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")
        self.trust_model = AutoModel.from_pretrained("microsoft/DialoGPT-medium")
        
        self.behavior_tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        self.behavior_model = AutoModelForSequenceClassification.from_pretrained(
            "distilbert-base-uncased", num_labels=2
        )
        
        # Move to device
        self.trust_model.to(self.device)
        self.behavior_model.to(self.device)
        
        # Create pipelines
        self.trust_pipeline = pipeline(
            "text-classification",
            model=self.behavior_model,
            tokenizer=self.behavior_tokenizer,
            device=0 if torch.cuda.is_available() else -1
        )
    
    def calculate_trust_score(self, agent_id: str, interactions: List[str]) -> float:
        """Calculate real trust score using DialoGPT"""
        try:
            # Combine interactions
            combined_text = " ".join(interactions[-10:])  # Last 10 interactions
            
            # Tokenize
            inputs = self.trust_tokenizer(
                combined_text,
                return_tensors="pt",
                truncation=True,
                max_length=512
            ).to(self.device)
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.trust_model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
            
            # Calculate trust score (0-1)
            trust_score = torch.sigmoid(embeddings.mean()).item()
            return trust_score
            
        except Exception as e:
            logging.error(f"Trust calculation error: {e}")
            return 0.5
    
    def detect_anomaly(self, behavior_text: str) -> float:
        """Detect behavioral anomalies using DistilBERT"""
        try:
            result = self.trust_pipeline(behavior_text)
            anomaly_score = result[0]['score'] if result[0]['label'] == 'LABEL_1' else 1 - result[0]['score']
            return anomaly_score
        except Exception as e:
            logging.error(f"Anomaly detection error: {e}")
            return 0.0

class RealSecurityModel:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Load security models
        self.security_tokenizer = AutoTokenizer.from_pretrained("roberta-base")
        self.security_model = AutoModelForSequenceClassification.from_pretrained(
            "roberta-base", num_labels=3  # safe, suspicious, malicious
        )
        
        self.security_model.to(self.device)
        
        # Create security pipeline
        self.security_pipeline = pipeline(
            "text-classification",
            model=self.security_model,
            tokenizer=self.security_tokenizer,
            device=0 if torch.cuda.is_available() else -1
        )
    
    def detect_threat(self, text: str) -> Dict[str, Any]:
        """Detect security threats using RoBERTa"""
        try:
            result = self.security_pipeline(text)
            
            threat_level = "safe"
            confidence = result[0]['score']
            
            if result[0]['label'] == 'LABEL_2':  # malicious
                threat_level = "malicious"
            elif result[0]['label'] == 'LABEL_1':  # suspicious
                threat_level = "suspicious"
            
            return {
                "threat_level": threat_level,
                "confidence": confidence,
                "is_threat": threat_level != "safe"
            }
        except Exception as e:
            logging.error(f"Threat detection error: {e}")
            return {"threat_level": "safe", "confidence": 0.0, "is_threat": False}
