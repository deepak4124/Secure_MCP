"""
Unit tests for Identity Manager
"""

import pytest
import time
from unittest.mock import Mock, patch
from mcp_security_framework.core.identity import (
    IdentityManager, AgentType, IdentityStatus, AgentIdentity
)


class TestIdentityManager:
    """Test cases for IdentityManager"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.identity_manager = IdentityManager()
        self.test_agent_id = "test_agent_001"
        self.test_public_key = b"test_public_key_data"
        self.test_agent_type = AgentType.WORKER
        self.test_capabilities = ["read", "write", "execute"]
        self.test_metadata = {"department": "engineering", "role": "developer"}
    
    def test_register_agent_success(self):
        """Test successful agent registration"""
        result = self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        assert result is True
        assert self.test_agent_id in self.identity_manager.agents
        agent = self.identity_manager.agents[self.test_agent_id]
        assert agent.agent_id == self.test_agent_id
        assert agent.public_key == self.test_public_key
        assert agent.agent_type == self.test_agent_type
        assert agent.capabilities == self.test_capabilities
        assert agent.metadata == self.test_metadata
        assert agent.status == IdentityStatus.ACTIVE
    
    def test_register_agent_duplicate(self):
        """Test registering duplicate agent"""
        # Register agent first time
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Try to register same agent again
        result = self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=b"different_key",
            agent_type=AgentType.COORDINATOR,
            capabilities=["admin"],
            metadata={"role": "admin"}
        )
        
        assert result is False
    
    def test_authenticate_agent_success(self):
        """Test successful agent authentication"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Authenticate agent
        result = self.identity_manager.authenticate_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key
        )
        
        assert result is True
    
    def test_authenticate_agent_invalid_key(self):
        """Test authentication with invalid key"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Authenticate with wrong key
        result = self.identity_manager.authenticate_agent(
            agent_id=self.test_agent_id,
            public_key=b"wrong_key"
        )
        
        assert result is False
    
    def test_authenticate_agent_not_found(self):
        """Test authentication of non-existent agent"""
        result = self.identity_manager.authenticate_agent(
            agent_id="non_existent_agent",
            public_key=self.test_public_key
        )
        
        assert result is False
    
    def test_revoke_agent_identity(self):
        """Test agent identity revocation"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Revoke identity
        result = self.identity_manager.revoke_agent_identity(self.test_agent_id)
        
        assert result is True
        agent = self.identity_manager.agents[self.test_agent_id]
        assert agent.status == IdentityStatus.REVOKED
    
    def test_revoke_agent_identity_not_found(self):
        """Test revoking non-existent agent identity"""
        result = self.identity_manager.revoke_agent_identity("non_existent_agent")
        
        assert result is False
    
    def test_get_agent_identity(self):
        """Test getting agent identity"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Get agent identity
        identity = self.identity_manager.get_agent_identity(self.test_agent_id)
        
        assert identity is not None
        assert identity.agent_id == self.test_agent_id
        assert identity.public_key == self.test_public_key
        assert identity.agent_type == self.test_agent_type
    
    def test_get_agent_identity_not_found(self):
        """Test getting non-existent agent identity"""
        identity = self.identity_manager.get_agent_identity("non_existent_agent")
        
        assert identity is None
    
    def test_list_active_agents(self):
        """Test listing active agents"""
        # Register multiple agents
        agents_data = [
            ("agent_1", AgentType.WORKER),
            ("agent_2", AgentType.COORDINATOR),
            ("agent_3", AgentType.MONITOR)
        ]
        
        for agent_id, agent_type in agents_data:
            self.identity_manager.register_agent(
                agent_id=agent_id,
                public_key=f"key_{agent_id}".encode(),
                agent_type=agent_type,
                capabilities=["basic"],
                metadata={}
            )
        
        # Revoke one agent
        self.identity_manager.revoke_agent_identity("agent_2")
        
        # List active agents
        active_agents = self.identity_manager.list_active_agents()
        
        assert len(active_agents) == 2
        agent_ids = [agent.agent_id for agent in active_agents]
        assert "agent_1" in agent_ids
        assert "agent_3" in agent_ids
        assert "agent_2" not in agent_ids
    
    def test_update_agent_capabilities(self):
        """Test updating agent capabilities"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Update capabilities
        new_capabilities = ["read", "write", "execute", "admin"]
        result = self.identity_manager.update_agent_capabilities(
            self.test_agent_id, new_capabilities
        )
        
        assert result is True
        agent = self.identity_manager.agents[self.test_agent_id]
        assert agent.capabilities == new_capabilities
    
    def test_update_agent_capabilities_not_found(self):
        """Test updating capabilities for non-existent agent"""
        result = self.identity_manager.update_agent_capabilities(
            "non_existent_agent", ["admin"]
        )
        
        assert result is False
    
    def test_validate_agent_capability(self):
        """Test validating agent capability"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Test valid capability
        assert self.identity_manager.validate_agent_capability(
            self.test_agent_id, "read"
        ) is True
        
        # Test invalid capability
        assert self.identity_manager.validate_agent_capability(
            self.test_agent_id, "admin"
        ) is False
        
        # Test non-existent agent
        assert self.identity_manager.validate_agent_capability(
            "non_existent_agent", "read"
        ) is False
    
    def test_generate_identity_proof(self):
        """Test generating identity proof"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Generate identity proof
        proof = self.identity_manager.generate_identity_proof(self.test_agent_id)
        
        assert proof is not None
        assert "agent_id" in proof
        assert "timestamp" in proof
        assert "signature" in proof
        assert proof["agent_id"] == self.test_agent_id
    
    def test_generate_identity_proof_not_found(self):
        """Test generating proof for non-existent agent"""
        proof = self.identity_manager.generate_identity_proof("non_existent_agent")
        
        assert proof is None
    
    def test_verify_identity_proof(self):
        """Test verifying identity proof"""
        # Register agent first
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Generate and verify proof
        proof = self.identity_manager.generate_identity_proof(self.test_agent_id)
        result = self.identity_manager.verify_identity_proof(proof)
        
        assert result is True
    
    def test_verify_identity_proof_invalid(self):
        """Test verifying invalid identity proof"""
        invalid_proof = {
            "agent_id": "fake_agent",
            "timestamp": time.time(),
            "signature": "fake_signature"
        }
        
        result = self.identity_manager.verify_identity_proof(invalid_proof)
        
        assert result is False
    
    def test_cleanup_expired_identities(self):
        """Test cleaning up expired identities"""
        # Register agent with short expiration
        with patch.object(self.identity_manager, 'identity_expiration', 0.1):
            self.identity_manager.register_agent(
                agent_id=self.test_agent_id,
                public_key=self.test_public_key,
                agent_type=self.test_agent_type,
                capabilities=self.test_capabilities,
                metadata=self.test_metadata
            )
            
            # Wait for expiration
            time.sleep(0.2)
            
            # Cleanup expired identities
            cleaned_count = self.identity_manager.cleanup_expired_identities()
            
            assert cleaned_count == 1
            assert self.test_agent_id not in self.identity_manager.agents
    
    def test_audit_log_creation(self):
        """Test that audit logs are created for operations"""
        initial_log_count = len(self.identity_manager.audit_log)
        
        # Register agent
        self.identity_manager.register_agent(
            agent_id=self.test_agent_id,
            public_key=self.test_public_key,
            agent_type=self.test_agent_type,
            capabilities=self.test_capabilities,
            metadata=self.test_metadata
        )
        
        # Check audit log
        assert len(self.identity_manager.audit_log) > initial_log_count
        latest_log = self.identity_manager.audit_log[-1]
        assert latest_log["action"] == "register_agent"
        assert latest_log["agent_id"] == self.test_agent_id


