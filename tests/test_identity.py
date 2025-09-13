"""
Tests for Identity Management System
"""

import pytest
import time
from mcp_security_framework.core.identity import (
    IdentityManager, AgentType, IdentityStatus, IdentityProof
)


class TestIdentityManager:
    """Test cases for IdentityManager"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.identity_manager = IdentityManager()
        self.test_agent_id = "test_agent_001"
        self.test_public_key = b"test_public_key"
        self.test_agent_type = AgentType.WORKER
        self.test_capabilities = ["tool_execution", "data_processing"]
        self.test_metadata = {"department": "test", "clearance": "confidential"}
    
    def test_register_agent_success(self):
        """Test successful agent registration"""
        success, message = self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        assert success is True
        assert "successfully" in message.lower()
        assert self.test_agent_id in self.identity_manager.identities
    
    def test_register_agent_duplicate(self):
        """Test duplicate agent registration"""
        # Register agent first time
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Try to register again
        success, message = self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        assert success is False
        assert "already exists" in message.lower()
    
    def test_verify_agent_identity(self):
        """Test agent identity verification"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Activate agent
        self.identity_manager.activate_identity(self.test_agent_id)
        
        # Test verification (simplified for demo)
        # In real implementation, this would use proper cryptographic verification
        result = self.identity_manager.verify_agent_identity(
            agent_id=self.test_agent_id,
            signature=b"test_signature",
            message=b"test_message"
        )
        
        # For demo purposes, this will fail due to simplified implementation
        assert result is False
    
    def test_generate_identity_proof(self):
        """Test identity proof generation"""
        # Register and activate agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        self.identity_manager.activate_identity(self.test_agent_id)
        
        # Generate proof
        proof = self.identity_manager.generate_identity_proof(self.test_agent_id)
        
        assert proof is not None
        assert isinstance(proof, IdentityProof)
        assert proof.challenge is not None
        assert proof.timestamp > 0
    
    def test_revoke_identity(self):
        """Test identity revocation"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Revoke identity
        result = self.identity_manager.revoke_identity(self.test_agent_id, "Test revocation")
        
        assert result is True
        assert self.test_agent_id in self.identity_manager.revoked_identities
        assert self.identity_manager.identities[self.test_agent_id].status == IdentityStatus.REVOKED
    
    def test_suspend_identity(self):
        """Test identity suspension"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Suspend identity
        result = self.identity_manager.suspend_identity(self.test_agent_id, "Test suspension")
        
        assert result is True
        assert self.identity_manager.identities[self.test_agent_id].status == IdentityStatus.SUSPENDED
    
    def test_activate_identity(self):
        """Test identity activation"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Activate identity
        result = self.identity_manager.activate_identity(self.test_agent_id)
        
        assert result is True
        assert self.identity_manager.identities[self.test_agent_id].status == IdentityStatus.ACTIVE
    
    def test_get_agent_identity(self):
        """Test getting agent identity"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Get identity
        identity = self.identity_manager.get_agent_identity(self.test_agent_id)
        
        assert identity is not None
        assert identity.agent_id == self.test_agent_id
        assert identity.agent_type == self.test_agent_type
        assert identity.capabilities == self.test_capabilities
        assert identity.metadata == self.test_metadata
    
    def test_list_active_agents(self):
        """Test listing active agents"""
        # Register multiple agents
        agents = [
            ("agent_001", AgentType.WORKER),
            ("agent_002", AgentType.COORDINATOR),
            ("agent_003", AgentType.MONITOR)
        ]
        
        for agent_id, agent_type in agents:
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=b"test_key",
                agent_type=agent_type,
                capabilities=["test"]
            )
            self.identity_manager.activate_identity(agent_id)
        
        # Suspend one agent
        self.identity_manager.suspend_identity("agent_002")
        
        # List active agents
        active_agents = self.identity_manager.list_active_agents()
        
        assert len(active_agents) == 2
        agent_ids = [agent.agent_id for agent in active_agents]
        assert "agent_001" in agent_ids
        assert "agent_003" in agent_ids
        assert "agent_002" not in agent_ids
    
    def test_update_trust_score(self):
        """Test updating agent trust score"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Update trust score
        result = self.identity_manager.update_trust_score(self.test_agent_id, 0.8)
        
        assert result is True
        assert self.identity_manager.identities[self.test_agent_id].trust_score == 0.8
    
    def test_update_trust_score_invalid(self):
        """Test updating trust score with invalid values"""
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities
        )
        
        # Test invalid trust scores
        assert self.identity_manager.update_trust_score(self.test_agent_id, -0.1) is False
        assert self.identity_manager.update_trust_score(self.test_agent_id, 1.1) is False
        assert self.identity_manager.update_trust_score(self.test_agent_id, 0.5) is True
