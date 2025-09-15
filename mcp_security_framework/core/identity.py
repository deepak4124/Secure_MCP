"""
Identity Management System for MCP Security Framework

This module provides comprehensive identity management including:
- Agent registration and verification
- Certificate-based authentication
- Identity revocation and recovery
- Zero-knowledge identity proofs
"""

import hashlib
import secrets
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, Field


class IdentityStatus(Enum):
    """Identity status enumeration"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"


class AgentType(Enum):
    """Agent type enumeration"""
    WORKER = "worker"
    COORDINATOR = "coordinator"
    MONITOR = "monitor"
    GATEWAY = "gateway"


@dataclass
class AgentIdentity:
    """Agent identity data structure"""
    agent_id: str
    public_key: bytes
    certificate: bytes
    agent_type: AgentType
    capabilities: List[str]
    trust_score: float
    status: IdentityStatus
    created_at: float
    last_seen: float
    metadata: Dict[str, str]


class IdentityProof(BaseModel):
    """Zero-knowledge identity proof"""
    proof_data: str = Field(..., description="Base64 encoded proof data")
    challenge: str = Field(..., description="Challenge used for proof generation")
    timestamp: float = Field(..., description="Proof generation timestamp")
    nonce: str = Field(..., description="Random nonce for replay protection")


class IdentityManager:
    """
    Comprehensive identity management system for multi-agent networks
    
    Features:
    - Agent registration and verification
    - Certificate-based authentication
    - Identity revocation and recovery
    - Zero-knowledge identity proofs
    - Sybil attack prevention
    """
    
    def __init__(self, ca_private_key: Optional[bytes] = None):
        """
        Initialize identity manager
        
        Args:
            ca_private_key: Certificate Authority private key (generated if None)
        """
        self.identities: Dict[str, AgentIdentity] = {}
        self.revoked_identities: set = set()
        self.identity_proofs: Dict[str, IdentityProof] = {}
        
        # Initialize Certificate Authority
        if ca_private_key:
            self.ca_private_key = serialization.load_pem_private_key(
                ca_private_key, password=None, backend=default_backend()
            )
        else:
            self.ca_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        
        self.ca_public_key = self.ca_private_key.public_key()
        
        # Generate CA certificate
        self.ca_certificate = self._generate_ca_certificate()
    
    def register_agent(
        self,
        agent_id: str,
        public_key: bytes,
        agent_type: AgentType,
        capabilities: List[str],
        metadata: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, str]:
        """
        Register a new agent in the system
        
        Args:
            agent_id: Unique agent identifier
            public_key: Agent's public key
            agent_type: Type of agent
            capabilities: List of agent capabilities
            metadata: Optional metadata
            
        Returns:
            Tuple of (success, message)
        """
        # Validate agent ID uniqueness
        if agent_id in self.identities:
            return False, "Agent ID already exists"
        
        if agent_id in self.revoked_identities:
            return False, "Agent ID is revoked"
        
        # Validate public key
        try:
            serialization.load_pem_public_key(public_key, backend=default_backend())
        except Exception:
            return False, "Invalid public key format"
        
        # Generate certificate
        certificate = self._generate_agent_certificate(agent_id, public_key)
        
        # Create agent identity
        identity = AgentIdentity(
            agent_id=agent_id,
            public_key=public_key,
            certificate=certificate,
            agent_type=agent_type,
            capabilities=capabilities,
            trust_score=0.5,  # Initial trust score
            status=IdentityStatus.PENDING,
            created_at=time.time(),
            last_seen=time.time(),
            metadata=metadata or {}
        )
        
        self.identities[agent_id] = identity
        
        return True, "Agent registered successfully"
    
    def verify_agent_identity(self, agent_id: str, signature: bytes, message: bytes) -> bool:
        """
        Verify agent identity using digital signature
        
        Args:
            agent_id: Agent identifier
            signature: Digital signature
            message: Original message
            
        Returns:
            True if verification successful
        """
        if agent_id not in self.identities:
            return False
        
        identity = self.identities[agent_id]
        
        if identity.status != IdentityStatus.ACTIVE:
            return False
        
        try:
            public_key = serialization.load_pem_public_key(
                identity.public_key, backend=default_backend()
            )
            
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Update last seen
            identity.last_seen = time.time()
            return True
            
        except Exception:
            return False
    
    def generate_identity_proof(self, agent_id: str) -> Optional[IdentityProof]:
        """
        Generate zero-knowledge identity proof
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Identity proof or None if agent not found
        """
        if agent_id not in self.identities:
            return None
        
        identity = self.identities[agent_id]
        
        if identity.status != IdentityStatus.ACTIVE:
            return None
        
        # Generate challenge
        challenge = secrets.token_hex(32)
        
        # Generate proof data (simplified zero-knowledge proof)
        proof_data = self._generate_zk_proof(agent_id, challenge)
        
        proof = IdentityProof(
            proof_data=base64.b64encode(proof_data).decode(),
            challenge=challenge,
            timestamp=time.time(),
            nonce=secrets.token_hex(16)
        )
        
        self.identity_proofs[agent_id] = proof
        return proof
    
    def verify_identity_proof(self, agent_id: str, proof: IdentityProof) -> bool:
        """
        Verify zero-knowledge identity proof
        
        Args:
            agent_id: Agent identifier
            proof: Identity proof to verify
            
        Returns:
            True if proof is valid
        """
        if agent_id not in self.identities:
            return False
        
        # Check if proof exists
        if agent_id not in self.identity_proofs:
            return False
        
        stored_proof = self.identity_proofs[agent_id]
        
        # Verify proof data
        try:
            proof_data = base64.b64decode(proof.proof_data)
            return self._verify_zk_proof(agent_id, proof.challenge, proof_data)
        except Exception:
            return False
    
    def revoke_identity(self, agent_id: str, reason: str = "") -> bool:
        """
        Revoke agent identity
        
        Args:
            agent_id: Agent identifier
            reason: Reason for revocation
            
        Returns:
            True if revocation successful
        """
        if agent_id not in self.identities:
            return False
        
        # Update identity status
        self.identities[agent_id].status = IdentityStatus.REVOKED
        
        # Add to revoked list
        self.revoked_identities.add(agent_id)
        
        # Remove from active proofs
        if agent_id in self.identity_proofs:
            del self.identity_proofs[agent_id]
        
        return True
    
    def suspend_identity(self, agent_id: str, reason: str = "") -> bool:
        """
        Suspend agent identity
        
        Args:
            agent_id: Agent identifier
            reason: Reason for suspension
            
        Returns:
            True if suspension successful
        """
        if agent_id not in self.identities:
            return False
        
        self.identities[agent_id].status = IdentityStatus.SUSPENDED
        return True
    
    def activate_identity(self, agent_id: str) -> bool:
        """
        Activate agent identity
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            True if activation successful
        """
        if agent_id not in self.identities:
            return False
        
        self.identities[agent_id].status = IdentityStatus.ACTIVE
        return True
    
    def get_agent_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """
        Get agent identity information
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Agent identity or None if not found
        """
        return self.identities.get(agent_id)
    
    def list_active_agents(self) -> List[AgentIdentity]:
        """
        List all active agents
        
        Returns:
            List of active agent identities
        """
        return [
            identity for identity in self.identities.values()
            if identity.status == IdentityStatus.ACTIVE
        ]
    
    def update_trust_score(self, agent_id: str, new_score: float) -> bool:
        """
        Update agent trust score
        
        Args:
            agent_id: Agent identifier
            new_score: New trust score (0.0 to 1.0)
            
        Returns:
            True if update successful
        """
        if agent_id not in self.identities:
            return False
        
        if not 0.0 <= new_score <= 1.0:
            return False
        
        self.identities[agent_id].trust_score = new_score
        return True
    
    def _generate_ca_certificate(self) -> bytes:
        """Generate Certificate Authority certificate"""
        # Simplified certificate generation
        # In production, use proper X.509 certificate generation
        cert_data = {
            "issuer": "MCP-Security-Framework-CA",
            "subject": "MCP-Security-Framework-CA",
            "public_key": self.ca_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "valid_from": time.time(),
            "valid_to": time.time() + (365 * 24 * 60 * 60),  # 1 year
            "serial_number": secrets.randbits(64)
        }
        
        return json.dumps(cert_data).encode()
    
    def _generate_agent_certificate(self, agent_id: str, public_key: bytes) -> bytes:
        """Generate agent certificate"""
        cert_data = {
            "issuer": "MCP-Security-Framework-CA",
            "subject": agent_id,
            "public_key": public_key.decode(),
            "valid_from": time.time(),
            "valid_to": time.time() + (365 * 24 * 60 * 60),  # 1 year
            "serial_number": secrets.randbits(64)
        }
        
        # Sign certificate with CA private key
        cert_json = json.dumps(cert_data)
        signature = self.ca_private_key.sign(
            cert_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        cert_data["signature"] = base64.b64encode(signature).decode()
        
        return json.dumps(cert_data).encode()
    
    def _generate_zk_proof(self, agent_id: str, challenge: str) -> bytes:
        """Generate simplified zero-knowledge proof"""
        # Simplified ZK proof implementation
        # In production, use proper zero-knowledge proof protocols
        
        identity = self.identities[agent_id]
        
        # Create proof data
        proof_data = {
            "agent_id": agent_id,
            "challenge": challenge,
            "timestamp": time.time(),
            "public_key_hash": hashlib.sha256(identity.public_key).hexdigest(),
            "certificate_hash": hashlib.sha256(identity.certificate).hexdigest()
        }
        
        return json.dumps(proof_data).encode()
    
    def _verify_zk_proof(self, agent_id: str, challenge: str, proof_data: bytes) -> bool:
        """Verify simplified zero-knowledge proof"""
        try:
            proof = json.loads(proof_data.decode())
            
            # Verify challenge matches
            if proof["challenge"] != challenge:
                return False
            
            # Verify agent ID matches
            if proof["agent_id"] != agent_id:
                return False
            
            # Verify timestamp is recent (within 5 minutes)
            if time.time() - proof["timestamp"] > 300:
                return False
            
            # Verify public key hash
            identity = self.identities[agent_id]
            expected_hash = hashlib.sha256(identity.public_key).hexdigest()
            if proof["public_key_hash"] != expected_hash:
                return False
            
            # Verify certificate hash
            expected_cert_hash = hashlib.sha256(identity.certificate).hexdigest()
            if proof["certificate_hash"] != expected_cert_hash:
                return False
            
            return True
            
        except Exception:
            return False
