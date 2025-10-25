"""
Pytest configuration and fixtures for MCP Security Framework tests
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch
from mcp_security_framework.core import IdentityManager, TrustCalculator, PolicyEngine, ToolRegistry
from mcp_security_framework.core.identity import AgentType
from mcp_security_framework.core.policy import AccessPolicy, PolicyDecision
from mcp_security_framework.core.trust import TrustEvent, TrustEventType


@pytest.fixture
def identity_manager():
    """Fixture for IdentityManager"""
    return IdentityManager()


@pytest.fixture
def trust_calculator():
    """Fixture for TrustCalculator"""
    return TrustCalculator()


@pytest.fixture
def policy_engine():
    """Fixture for PolicyEngine"""
    return PolicyEngine()


@pytest.fixture
def tool_registry():
    """Fixture for ToolRegistry"""
    return ToolRegistry()


@pytest.fixture
def sample_agent_data():
    """Fixture for sample agent data"""
    return {
        "agent_id": "test_agent_001",
        "public_key": b"test_public_key_data",
        "agent_type": AgentType.WORKER,
        "capabilities": ["read", "write", "execute"],
        "metadata": {"department": "engineering", "role": "developer"}
    }


@pytest.fixture
def sample_policy():
    """Fixture for sample policy"""
    return AccessPolicy(
        policy_id="test_policy_001",
        name="Test Policy",
        description="Test policy for unit testing",
        rules=[
            {
                "condition": "agent_type == 'worker'",
                "action": "allow",
                "reason": "Worker agent access"
            }
        ],
        priority=1
    )


@pytest.fixture
def sample_trust_events():
    """Fixture for sample trust events"""
    return [
        TrustEvent(
            event_id="event_1",
            agent_id="test_agent_001",
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=1000.0,
            value=0.8
        ),
        TrustEvent(
            event_id="event_2",
            agent_id="test_agent_001",
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=1001.0,
            value=0.9
        ),
        TrustEvent(
            event_id="event_3",
            agent_id="test_agent_001",
            event_type=TrustEventType.TASK_SUCCESS,
            timestamp=1002.0,
            value=0.85
        )
    ]


@pytest.fixture
def mock_real_models():
    """Fixture for mocked real models"""
    with patch('mcp_security_framework.models.real_models.RealTrustModel') as mock_trust, \
         patch('mcp_security_framework.models.real_models.RealSecurityModel') as mock_security:
        
        # Setup trust model mock
        mock_trust.return_value = Mock()
        mock_trust.return_value.calculate_trust_score.return_value = 0.8
        mock_trust.return_value.detect_anomaly.return_value = 0.1
        
        # Setup security model mock
        mock_security.return_value = Mock()
        mock_security.return_value.detect_threat.return_value = {
            "threat_level": "safe",
            "confidence": 0.9,
            "is_threat": False
        }
        
        yield mock_trust, mock_security


@pytest.fixture
def temp_config_file():
    """Fixture for temporary configuration file"""
    config_content = """
security:
  encryption:
    algorithm: "AES-256"
    key_size: 256
  authentication:
    method: "certificate"
    timeout: 300
  trust:
    min_events: 5
    decay_factor: 0.95
  policy:
    default_action: "deny"
    evaluation_timeout: 10
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    try:
        os.unlink(temp_file)
    except OSError:
        pass


@pytest.fixture
def event_loop():
    """Fixture for asyncio event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture
def mock_gateway_components():
    """Fixture for mocked gateway components"""
    identity_manager = Mock(spec=IdentityManager)
    trust_calculator = Mock(spec=TrustCalculator)
    policy_engine = Mock(spec=PolicyEngine)
    tool_registry = Mock(spec=ToolRegistry)
    
    # Setup default mock behaviors
    identity_manager.authenticate_agent.return_value = True
    identity_manager.get_agent_identity.return_value = Mock()
    
    trust_calculator.get_trust_score.return_value = Mock()
    trust_calculator.get_trust_score.return_value.overall_score = 0.8
    
    policy_engine.evaluate_all_policies.return_value = Mock()
    policy_engine.evaluate_all_policies.return_value.decision = PolicyAction.ALLOW
    
    return {
        'identity_manager': identity_manager,
        'trust_calculator': trust_calculator,
        'policy_engine': policy_engine,
        'tool_registry': tool_registry
    }


@pytest.fixture
def benchmark_config():
    """Fixture for benchmark configuration"""
    from mcp_security_framework.benchmarking import BenchmarkConfig, BenchmarkScope
    
    return BenchmarkConfig(
        scope=BenchmarkScope.COMPREHENSIVE,
        iterations=3,
        timeout=30,
        concurrent_requests=5
    )


@pytest.fixture
def sample_benchmark_results():
    """Fixture for sample benchmark results"""
    return {
        "security_results": {
            "total_tests": 10,
            "threats_detected": 8,
            "false_positives": 1,
            "false_negatives": 1,
            "detection_accuracy": 0.9
        },
        "performance_results": {
            "total_requests": 1000,
            "successful_requests": 950,
            "duration": 10.5,
            "throughput": 90.48,
            "average_response_time": 0.11
        },
        "trust_results": {
            "trust_scores": {
                "agent_1": 0.8,
                "agent_2": 0.7,
                "agent_3": 0.9
            },
            "average_trust": 0.8,
            "trust_variance": 0.1
        },
        "real_metrics": {
            "framework_metrics": {
                "requests_processed": 1000,
                "threats_detected": 50,
                "average_response_time": 0.1,
                "threat_detection_rate": 0.05,
                "throughput": 1000
            },
            "model_performance": {
                "trust_model_loaded": True,
                "security_model_loaded": True
            },
            "system_metrics": {
                "memory_usage": "monitored",
                "cpu_usage": "monitored",
                "gpu_usage": "not_available"
            }
        },
        "timestamp": 1234567890.0
    }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Add asyncio marker to async tests
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)
        
        # Add unit marker to unit tests
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Add integration marker to integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


# Test utilities
class TestUtils:
    """Utility functions for tests"""
    
    @staticmethod
    def create_test_agent(identity_manager, agent_id="test_agent", agent_type=AgentType.WORKER):
        """Create a test agent"""
        return identity_manager.register_agent(
            agent_id=agent_id,
            public_key=f"key_{agent_id}".encode(),
            agent_type=agent_type,
            capabilities=["read", "write"],
            metadata={"test": True}
        )
    
    @staticmethod
    def create_test_policy(policy_engine, policy_id="test_policy", action="allow"):
        """Create a test policy"""
        policy = AccessPolicy(
            policy_id=policy_id,
            name=f"Test Policy {policy_id}",
            description="Test policy",
            rules=[
                {
                    "condition": "agent_type == 'worker'",
                    "action": action,
                    "reason": f"Test policy for {action}"
                }
            ],
            priority=1
        )
        return policy_engine.add_policy(policy)
    
    @staticmethod
    def create_test_trust_events(trust_calculator, agent_id="test_agent", count=6):
        """Create test trust events"""
        events = []
        for i in range(count):
            event = TrustEvent(
                event_id=f"event_{i}",
                agent_id=agent_id,
                event_type=TrustEventType.TASK_SUCCESS,
                timestamp=1000.0 + i,
                value=0.8
            )
            trust_calculator.add_trust_event(event)
            events.append(event)
        return events


@pytest.fixture
def test_utils():
    """Fixture for test utilities"""
    return TestUtils
