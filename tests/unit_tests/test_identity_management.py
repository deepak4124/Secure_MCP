"""
Unit tests for Identity Management System

This module contains comprehensive unit tests for the identity management
system including agent registration, authentication, and identity verification.
"""

import pytest
import time
import json
import sys
import os
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from security.authentication.identity_management import (
    IdentityManager, AgentType, IdentityStatus, AgentIdentity, IdentityProof
)


class TestIdentityManager:
    """Test cases for IdentityManager class"""
    
    @pytest.fixture
    def identity_manager(self):
        """Create a fresh IdentityManager instance for each test"""
        return IdentityManager()
    
    @pytest.fixture
    def test_keys(self):
        """Generate test cryptographic keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key
    
    def test_identity_manager_initialization(self, identity_manager):
        """Test IdentityManager initialization"""
        assert identity_manager is not None
        assert len(identity_manager.identities) == 0
        assert len(identity_manager.revoked_identities) == 0
        assert identity_manager.ca_private_key is not None
        assert identity_manager.ca_public_key is not None
    
    def test_agent_registration_success(self, identity_manager, test_keys):
        """Test successful agent registration"""
        private_key, public_key = test_keys
        
        success, message = identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing", "analysis"],
            metadata={"version": "1.0"}
        )
        
        assert success is True
        assert "successfully" in message.lower()
        assert "test_agent_001" in identity_manager.identities
    
    def test_agent_registration_duplicate_id(self, identity_manager, test_keys):
        """Test agent registration with duplicate ID"""
        private_key, public_key = test_keys
        
        # Register first agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        
        # Try to register second agent with same ID
        success, message = identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.COORDINATOR,
            capabilities=["coordination"]
        )
        
        assert success is False
        assert "already exists" in message.lower()
    
    def test_agent_registration_invalid_public_key(self, identity_manager):
        """Test agent registration with invalid public key"""
        invalid_public_key = b"invalid_public_key_data"
        
        success, message = identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=invalid_public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        
        assert success is False
        assert "invalid" in message.lower()
    
    def test_agent_identity_activation(self, identity_manager, test_keys):
        """Test agent identity activation"""
        private_key, public_key = test_keys
        
        # Register agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        
        # Check initial status
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.status == IdentityStatus.PENDING
        
        # Activate identity
        success = identity_manager.activate_identity("test_agent_001")
        assert success is True
        
        # Check updated status
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.status == IdentityStatus.ACTIVE
    
    def test_agent_identity_suspension(self, identity_manager, test_keys):
        """Test agent identity suspension"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Suspend identity
        success = identity_manager.suspend_identity("test_agent_001", "Test suspension")
        assert success is True
        
        # Check status
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.status == IdentityStatus.SUSPENDED
    
    def test_agent_identity_revocation(self, identity_manager, test_keys):
        """Test agent identity revocation"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Revoke identity
        success = identity_manager.revoke_identity("test_agent_001", "Test revocation")
        assert success is True
        
        # Check status
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.status == IdentityStatus.REVOKED
        assert "test_agent_001" in identity_manager.revoked_identities
    
    def test_identity_verification_success(self, identity_manager, test_keys):
        """Test successful identity verification"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Create test message and signature
        message = b"test message for verification"
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Verify identity
        is_valid = identity_manager.verify_agent_identity(
            "test_agent_001", signature, message
        )
        
        assert is_valid is True
    
    def test_identity_verification_failure(self, identity_manager, test_keys):
        """Test identity verification failure"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Create invalid signature
        message = b"test message for verification"
        invalid_signature = b"invalid_signature_data"
        
        # Verify identity (should fail)
        is_valid = identity_manager.verify_agent_identity(
            "test_agent_001", invalid_signature, message
        )
        
        assert is_valid is False
    
    def test_identity_verification_suspended_agent(self, identity_manager, test_keys):
        """Test identity verification for suspended agent"""
        private_key, public_key = test_keys
        
        # Register and suspend agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.suspend_identity("test_agent_001")
        
        # Create test message and signature
        message = b"test message for verification"
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Verify identity (should fail for suspended agent)
        is_valid = identity_manager.verify_agent_identity(
            "test_agent_001", signature, message
        )
        
        assert is_valid is False
    
    def test_identity_proof_generation(self, identity_manager, test_keys):
        """Test identity proof generation"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Generate identity proof
        proof = identity_manager.generate_identity_proof("test_agent_001")
        
        assert proof is not None
        assert proof.challenge is not None
        assert proof.timestamp > 0
        assert proof.nonce is not None
        assert proof.proof_data is not None
    
    def test_identity_proof_verification(self, identity_manager, test_keys):
        """Test identity proof verification"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Generate identity proof
        proof = identity_manager.generate_identity_proof("test_agent_001")
        assert proof is not None
        
        # Verify identity proof
        is_valid = identity_manager.verify_identity_proof("test_agent_001", proof)
        assert is_valid is True
    
    def test_identity_proof_verification_invalid(self, identity_manager, test_keys):
        """Test identity proof verification with invalid proof"""
        private_key, public_key = test_keys
        
        # Register and activate agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        identity_manager.activate_identity("test_agent_001")
        
        # Create invalid proof
        invalid_proof = IdentityProof(
            proof_data="invalid_proof_data",
            challenge="invalid_challenge",
            timestamp=time.time(),
            nonce="invalid_nonce"
        )
        
        # Verify identity proof (should fail)
        is_valid = identity_manager.verify_identity_proof("test_agent_001", invalid_proof)
        assert is_valid is False
    
    def test_trust_score_update(self, identity_manager, test_keys):
        """Test trust score update"""
        private_key, public_key = test_keys
        
        # Register agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        
        # Check initial trust score
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.trust_score == 0.5
        
        # Update trust score
        success = identity_manager.update_trust_score("test_agent_001", 0.8)
        assert success is True
        
        # Check updated trust score
        identity = identity_manager.get_agent_identity("test_agent_001")
        assert identity.trust_score == 0.8
    
    def test_trust_score_update_invalid(self, identity_manager, test_keys):
        """Test trust score update with invalid values"""
        private_key, public_key = test_keys
        
        # Register agent
        identity_manager.register_agent(
            agent_id="test_agent_001",
            public_key=public_key,
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"]
        )
        
        # Try to update with invalid trust score
        success = identity_manager.update_trust_score("test_agent_001", 1.5)
        assert success is False
        
        success = identity_manager.update_trust_score("test_agent_001", -0.1)
        assert success is False
    
    def test_list_active_agents(self, identity_manager, test_keys):
        """Test listing active agents"""
        private_key, public_key = test_keys
        
        # Register multiple agents
        for i in range(3):
            identity_manager.register_agent(
                agent_id=f"test_agent_{i:03d}",
                public_key=public_key,
                agent_type=AgentType.WORKER,
                capabilities=["data_processing"]
            )
        
        # Activate only first two agents
        identity_manager.activate_identity("test_agent_000")
        identity_manager.activate_identity("test_agent_001")
        
        # List active agents
        active_agents = identity_manager.list_active_agents()
        assert len(active_agents) == 2
        
        agent_ids = [agent.agent_id for agent in active_agents]
        assert "test_agent_000" in agent_ids
        assert "test_agent_001" in agent_ids
        assert "test_agent_002" not in agent_ids
    
    def test_get_nonexistent_agent(self, identity_manager):
        """Test getting identity for nonexistent agent"""
        identity = identity_manager.get_agent_identity("nonexistent_agent")
        assert identity is None
    
    def test_activate_nonexistent_agent(self, identity_manager):
        """Test activating identity for nonexistent agent"""
        success = identity_manager.activate_identity("nonexistent_agent")
        assert success is False
    
    def test_suspend_nonexistent_agent(self, identity_manager):
        """Test suspending identity for nonexistent agent"""
        success = identity_manager.suspend_identity("nonexistent_agent")
        assert success is False
    
    def test_revoke_nonexistent_agent(self, identity_manager):
        """Test revoking identity for nonexistent agent"""
        success = identity_manager.revoke_identity("nonexistent_agent")
        assert success is False


class TestAgentIdentity:
    """Test cases for AgentIdentity class"""
    
    def test_agent_identity_creation(self, test_keys):
        """Test AgentIdentity creation"""
        private_key, public_key = test_keys
        
        identity = AgentIdentity(
            agent_id="test_agent_001",
            public_key=public_key,
            certificate=b"test_certificate",
            agent_type=AgentType.WORKER,
            capabilities=["data_processing"],
            trust_score=0.7,
            status=IdentityStatus.ACTIVE,
            created_at=time.time(),
            last_seen=time.time(),
            metadata={"version": "1.0"}
        )
        
        assert identity.agent_id == "test_agent_001"
        assert identity.public_key == public_key
        assert identity.agent_type == AgentType.WORKER
        assert identity.trust_score == 0.7
        assert identity.status == IdentityStatus.ACTIVE
        assert identity.metadata["version"] == "1.0"


class TestIdentityProof:
    """Test cases for IdentityProof class"""
    
    def test_identity_proof_creation(self):
        """Test IdentityProof creation"""
        proof = IdentityProof(
            proof_data="test_proof_data",
            challenge="test_challenge",
            timestamp=time.time(),
            nonce="test_nonce"
        )
        
        assert proof.proof_data == "test_proof_data"
        assert proof.challenge == "test_challenge"
        assert proof.timestamp > 0
        assert proof.nonce == "test_nonce"


if __name__ == "__main__":
    pytest.main([__file__])
