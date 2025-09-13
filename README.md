# MCP Security Framework

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://img.shields.io/badge/tests-pytest-blue.svg)](https://pytest.org/)

A comprehensive security framework for Model Context Protocol (MCP) in Multi-Agent Systems (MAS). This framework provides identity management, trust calculation, tool verification, and secure execution across multiple MAS frameworks including LangGraph, AutoGen, CrewAI, and Semantic Kernel.

## 🚀 Features

### Core Security Components
- **Identity Management**: Agent registration, authentication, and certificate-based verification
- **Trust Calculation**: Multi-dimensional trust scoring with behavioral analysis and sybil detection
- **MCP Security Gateway**: Secure integration with MCP servers and tool verification
- **Policy Engine**: Access control and authorization with RBAC, CBAC, and ABAC support
- **Tool Registry**: Tool registration, verification, and supply chain attestation

### Multi-Agent System Support
- **LangGraph Adapter**: Secure workflow execution and node verification
- **AutoGen Adapter**: Secure conversation management and message encryption
- **CrewAI Adapter**: Secure crew management and task execution
- **Extensible Architecture**: Easy integration with other MAS frameworks

### Security Features
- **Zero-Knowledge Identity Proofs**: Privacy-preserving agent authentication
- **Trust-Aware Task Allocation**: Dynamic task assignment based on trust scores
- **Collusion Detection**: Advanced algorithms to detect and prevent agent collusion
- **Comprehensive Audit Logging**: Detailed security event tracking and analysis
- **Threat Detection**: Real-time monitoring and alerting for security threats

## 📦 Installation

### Basic Installation
```bash
pip install mcp-security-framework
```

### With MAS Framework Support
```bash
# LangGraph support
pip install mcp-security-framework[langgraph]

# AutoGen support
pip install mcp-security-framework[autogen]

# CrewAI support
pip install mcp-security-framework[crewai]

# All frameworks
pip install mcp-security-framework[langgraph,autogen,crewai]
```

### Development Installation
```bash
git clone https://github.com/mcp-security/framework.git
cd framework
pip install -e .[dev]
```

## 🏃‍♂️ Quick Start

### Basic Setup
```python
from mcp_security_framework import (
    IdentityManager, TrustCalculator, MCPSecurityGateway,
    PolicyEngine, ToolRegistry, LangGraphSecurityAdapter
)

# Initialize core components
identity_manager = IdentityManager()
trust_calculator = TrustCalculator()
mcp_gateway = MCPSecurityGateway()
policy_engine = PolicyEngine()
tool_registry = ToolRegistry()

# Create security adapter
security_adapter = LangGraphSecurityAdapter(
    identity_manager=identity_manager,
    trust_calculator=trust_calculator,
    policy_engine=policy_engine,
    mcp_gateway=mcp_gateway,
    tool_registry=tool_registry
)
```

### Register and Authenticate Agents
```python
# Register a new agent
success, message = await security_adapter.register_agent(
    agent_id="agent_001",
    agent_type="worker",
    capabilities=["tool_execution", "data_processing"],
    metadata={"department": "research", "clearance_level": "confidential"}
)

# Authenticate agent
authenticated = await security_adapter.authenticate_agent(
    agent_id="agent_001",
    credentials={"auth_token": "langgraph_agent_001"}
)
```

### Secure Tool Execution
```python
# Request tool access
allowed, reason = await security_adapter.request_tool_access(
    agent_id="agent_001",
    tool_id="data_analyzer",
    operation="execute",
    parameters={"dataset": "sensitive_data.csv"}
)

# Execute tool with security controls
if allowed:
    result = await security_adapter.execute_tool(
        agent_id="agent_001",
        tool_id="data_analyzer",
        parameters={"dataset": "sensitive_data.csv"}
    )
```

### Trust Management
```python
# Report trust events
await security_adapter.report_trust_event(
    agent_id="agent_001",
    event_type="task_success",
    event_data={
        "value": 0.8,
        "context": {"task": "data_analysis", "quality": "high"}
    }
)

# Get trust score
trust_score = trust_calculator.get_trust_score("agent_001")
print(f"Agent trust score: {trust_score.overall_score}")
```

## 🔧 Configuration

### Security Configuration
```yaml
# config/security_config.yaml
identity_management:
  require_authentication: true
  require_authorization: true
  session_timeout: 3600

trust_calculation:
  decay_factor: 0.95
  min_events: 5
  sybil_threshold: 0.8

mcp_integration:
  tool_verification:
    enabled: true
    signature_verification: true
    sandbox_execution: true

policy_engine:
  default_policies: true
  evaluation_timeout: 5.0

logging:
  level: INFO
  audit_logging: true
  log_file: logs/security.log
```

### Environment Variables
```bash
export MCP_SECURITY_REQUIRE_AUTH=true
export MCP_SECURITY_LOG_LEVEL=INFO
export MCP_SECURITY_SYBIL_THRESHOLD=0.8
export MCP_SECURITY_RATE_LIMITING=true
```

## 🏗️ Architecture

### Core Components
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Identity        │    │ Trust           │    │ MCP Security    │
│ Management      │◄──►│ Calculation     │◄──►│ Gateway         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Policy Engine   │    │ Tool Registry   │    │ Security        │
│                 │    │                 │    │ Adapters        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### MAS Framework Integration
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ LangGraph       │    │ AutoGen         │    │ CrewAI          │
│ Security        │    │ Security        │    │ Security        │
│ Adapter         │    │ Adapter         │    │ Adapter         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │ MCP Security    │
                    │ Framework       │
                    │ Core            │
                    └─────────────────┘
```

## 📚 Documentation

### API Reference
- [Identity Management](docs/identity.md)
- [Trust Calculation](docs/trust.md)
- [MCP Security Gateway](docs/gateway.md)
- [Policy Engine](docs/policy.md)
- [Tool Registry](docs/registry.md)
- [MAS Adapters](docs/adapters.md)

### Examples
- [Basic Usage](examples/basic_usage.py)
- [LangGraph Integration](examples/langgraph_integration.py)
- [AutoGen Integration](examples/autogen_integration.py)
- [CrewAI Integration](examples/crewai_integration.py)
- [Advanced Security](examples/advanced_security.py)

### Guides
- [Getting Started](docs/getting_started.md)
- [Configuration Guide](docs/configuration.md)
- [Security Best Practices](docs/security_best_practices.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_security_framework

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Security Tests**: Security feature validation
- **Performance Tests**: Load and stress testing

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/mcp-security/framework.git
cd framework
pip install -e .[dev]
pre-commit install
```

### Code Style
- **Black**: Code formatting
- **Flake8**: Linting
- **MyPy**: Type checking
- **Pre-commit**: Git hooks

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Model Context Protocol (MCP)**: For the foundational protocol
- **LangGraph**: For multi-agent workflow capabilities
- **AutoGen**: For conversational AI frameworks
- **CrewAI**: For collaborative agent systems
- **Security Research Community**: For trust and security algorithms

## 📞 Support

- **Documentation**: [https://mcp-security.readthedocs.io/](https://mcp-security.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/mcp-security/framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mcp-security/framework/discussions)
- **Email**: contact@mcp-security.org

## 🔮 Roadmap

### Version 0.2.0
- [ ] Enhanced threat detection algorithms
- [ ] Advanced trust modeling
- [ ] Performance optimizations
- [ ] Additional MAS framework support

### Version 0.3.0
- [ ] Distributed trust calculation
- [ ] Blockchain-based identity verification
- [ ] Advanced policy languages
- [ ] Real-time security monitoring

### Version 1.0.0
- [ ] Production-ready deployment
- [ ] Enterprise security features
- [ ] Compliance frameworks (SOC2, ISO27001)
- [ ] Commercial support

---

**Made with ❤️ by the Secure MCP Research Team**