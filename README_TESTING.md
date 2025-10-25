# MCP Security Framework - Testing Guide

This document provides comprehensive information about testing the MCP Security Framework, including unit tests, integration tests, and benchmarking validation.

## 🧪 Test Structure

```
tests/
├── __init__.py
├── conftest.py                 # Pytest configuration and fixtures
├── unit/                       # Unit tests
│   ├── __init__.py
│   ├── test_identity_manager.py
│   ├── test_trust_calculator.py
│   ├── test_policy_engine.py
│   └── test_real_models.py
└── integration/                # Integration tests
    ├── __init__.py
    ├── test_framework_integration.py
    └── test_benchmarking_integration.py
```

## 🚀 Quick Start

### 1. Install Test Dependencies

```bash
# Install test dependencies
pip install -r requirements_test.txt

# Or use the test runner
python run_tests.py --install-deps
```

### 2. Run All Tests

```bash
# Run all tests
python run_tests.py

# Run with verbose output
python run_tests.py --verbose

# Run with coverage report
python run_tests.py --coverage
```

### 3. Run Specific Test Types

```bash
# Unit tests only
python run_tests.py --type unit

# Integration tests only
python run_tests.py --type integration

# Benchmark tests only
python run_tests.py --type benchmark

# Model tests only
python run_tests.py --type model
```

## 📋 Test Categories

### Unit Tests

Unit tests focus on individual components in isolation:

- **Identity Manager**: Agent registration, authentication, revocation
- **Trust Calculator**: Trust scoring, event processing, ML integration
- **Policy Engine**: Policy evaluation, rule matching, violation tracking
- **Real Models**: ML model integration, threat detection, trust calculation

### Integration Tests

Integration tests verify component interactions:

- **Framework Integration**: Complete agent lifecycle, request processing
- **Trust-Policy Integration**: Trust-based policy decisions
- **Benchmarking Integration**: Performance and security validation
- **Error Handling**: Cross-component error scenarios

## 🔧 Test Configuration

### Pytest Configuration (`pytest.ini`)

```ini
[tool:pytest]
testpaths = tests
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
    asyncio: Async tests
    benchmark: Benchmark tests
    model: Model tests
asyncio_mode = auto
timeout = 300
```

### Test Fixtures (`conftest.py`)

The test suite includes comprehensive fixtures:

- `identity_manager`: IdentityManager instance
- `trust_calculator`: TrustCalculator instance
- `policy_engine`: PolicyEngine instance
- `tool_registry`: ToolRegistry instance
- `sample_agent_data`: Sample agent data
- `sample_policy`: Sample policy configuration
- `sample_trust_events`: Sample trust events
- `mock_real_models`: Mocked ML models
- `benchmark_config`: Benchmark configuration
- `test_utils`: Utility functions

## 🎯 Running Tests

### Using the Test Runner

```bash
# Basic usage
python run_tests.py

# With options
python run_tests.py --type unit --verbose --coverage --parallel

# Run specific test
python run_tests.py --test tests/unit/test_identity_manager.py::TestIdentityManager::test_register_agent_success

# Generate comprehensive report
python run_tests.py --report

# Lint test files
python run_tests.py --lint
```

### Using Pytest Directly

```bash
# Run all tests
pytest

# Run unit tests only
pytest -m unit

# Run integration tests only
pytest -m integration

# Run with coverage
pytest --cov=mcp_security_framework --cov-report=html

# Run in parallel
pytest -n auto

# Run specific test file
pytest tests/unit/test_identity_manager.py

# Run specific test function
pytest tests/unit/test_identity_manager.py::TestIdentityManager::test_register_agent_success
```

## 📊 Test Coverage

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=mcp_security_framework --cov-report=html

# Generate XML coverage report
pytest --cov=mcp_security_framework --cov-report=xml

# Generate terminal coverage report
pytest --cov=mcp_security_framework --cov-report=term
```

### Coverage Targets

- **Overall Coverage**: > 90%
- **Core Components**: > 95%
- **Integration Tests**: > 85%
- **ML Models**: > 80%

## 🧪 Test Examples

### Unit Test Example

```python
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
```

### Integration Test Example

```python
@pytest.mark.asyncio
async def test_gateway_request_processing(self):
    """Test complete request processing through gateway"""
    # Setup: Register agent and create policy
    agent_id = "gateway_test_agent"
    self.identity_manager.register_agent(...)
    
    # Create request
    request = RequestContext(
        operation="read",
        resource="test_resource",
        agent_id=agent_id
    )
    
    # Process request through gateway
    response = await self.gateway.process_request(agent_id, request)
    
    # Verify response
    assert response is not None
    assert isinstance(response, ResponseContext)
```

## 🔍 Test Validation

### Security Tests

- **Authentication**: Agent identity verification
- **Authorization**: Policy-based access control
- **Threat Detection**: ML-based threat identification
- **Trust Validation**: Trust score accuracy

### Performance Tests

- **Throughput**: Requests per second
- **Latency**: Response time measurements
- **Memory Usage**: Resource consumption
- **Concurrent Processing**: Multi-agent scenarios

### Reliability Tests

- **Error Handling**: Exception scenarios
- **Fault Tolerance**: Component failures
- **Data Consistency**: State management
- **Recovery**: System restoration

## 📈 Benchmarking Tests

### Security Benchmarking

```python
async def test_real_security_benchmark(self):
    """Test real security benchmarking"""
    security_results = await self.benchmark_runner._run_real_security_benchmark(self.real_gateway)
    
    assert "total_tests" in security_results
    assert "threats_detected" in security_results
    assert "detection_accuracy" in security_results
    assert 0.0 <= security_results["detection_accuracy"] <= 1.0
```

### Performance Benchmarking

```python
async def test_real_performance_benchmark(self):
    """Test real performance benchmarking"""
    performance_results = await self.benchmark_runner._run_real_performance_benchmark(self.real_gateway)
    
    assert performance_results["total_requests"] > 0
    assert performance_results["throughput"] > 0
    assert performance_results["average_response_time"] > 0
```

## 🐛 Debugging Tests

### Verbose Output

```bash
# Run with verbose output
pytest -v

# Run with extra verbose output
pytest -vv

# Show local variables on failure
pytest -l
```

### Test Debugging

```bash
# Run specific test with debugging
pytest tests/unit/test_identity_manager.py::TestIdentityManager::test_register_agent_success -v -s

# Run with pdb debugger
pytest --pdb

# Run with traceback
pytest --tb=long
```

## 📋 Test Checklist

### Before Running Tests

- [ ] Install all dependencies (`pip install -r requirements_test.txt`)
- [ ] Verify Python version (3.8+)
- [ ] Check virtual environment activation
- [ ] Ensure Hugging Face models are downloaded (for model tests)

### Test Execution

- [ ] Run unit tests (`python run_tests.py --type unit`)
- [ ] Run integration tests (`python run_tests.py --type integration`)
- [ ] Run benchmark tests (`python run_tests.py --type benchmark`)
- [ ] Generate coverage report (`python run_tests.py --coverage`)

### Validation

- [ ] All tests pass
- [ ] Coverage > 90%
- [ ] No critical warnings
- [ ] Performance benchmarks meet targets

## 🚨 Troubleshooting

### Common Issues

1. **Import Errors**: Ensure project root is in Python path
2. **Model Loading**: Verify Hugging Face models are downloaded
3. **Async Tests**: Use `pytest-asyncio` for async test support
4. **Memory Issues**: Reduce parallel test execution (`-n 1`)

### Performance Issues

```bash
# Run tests sequentially
pytest -n 1

# Skip slow tests
pytest -m "not slow"

# Run with memory profiling
pytest --memray
```

## 📊 Test Metrics

### Expected Results

- **Unit Tests**: 100+ test cases
- **Integration Tests**: 20+ test scenarios
- **Coverage**: > 90% overall
- **Execution Time**: < 5 minutes for full suite
- **Success Rate**: 100% pass rate

### Performance Benchmarks

- **Security Detection**: > 85% accuracy
- **Trust Calculation**: < 100ms per request
- **Policy Evaluation**: < 50ms per request
- **Throughput**: > 1000 requests/second

## 🔄 Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: pip install -r requirements_test.txt
    - name: Run tests
      run: python run_tests.py --coverage
```

## 📚 Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Pytest-Asyncio](https://pytest-asyncio.readthedocs.io/)
- [Coverage.py](https://coverage.readthedocs.io/)
- [Testing Best Practices](https://docs.python.org/3/library/unittest.html)

---

**Note**: This testing suite ensures the MCP Security Framework meets high standards for reliability, security, and performance. Regular test execution is essential for maintaining code quality and system integrity.

