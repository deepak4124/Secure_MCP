"""
Configuration management for MCP Security Framework

This module provides configuration loading, validation, and management
for the MCP Security Framework.
"""

import os
import yaml
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecurityConfig:
    """Security configuration data structure"""
    
    # Identity Management
    identity_management: Dict[str, Any] = field(default_factory=lambda: {
        "require_authentication": True,
        "require_authorization": True,
        "certificate_validation": True,
        "identity_proof_required": True,
        "session_timeout": 3600
    })
    
    # Trust Calculation
    trust_calculation: Dict[str, Any] = field(default_factory=lambda: {
        "decay_factor": 0.95,
        "min_events": 5,
        "window_size": 100,
        "sybil_threshold": 0.8,
        "collusion_threshold": 0.7
    })
    
    # MCP Integration
    mcp_integration: Dict[str, Any] = field(default_factory=lambda: {
        "server_security": {
            "require_authentication": True,
            "require_authorization": True,
            "tool_verification": True,
            "context_encryption": True
        },
        "tool_verification": {
            "enabled": True,
            "signature_verification": True,
            "capability_verification": True,
            "sandbox_execution": True
        },
        "discovery": {
            "auto_discover": True,
            "network_scan": False,
            "trusted_servers": ["localhost:3000"]
        }
    })
    
    # Policy Engine
    policy_engine: Dict[str, Any] = field(default_factory=lambda: {
        "default_policies": True,
        "policy_file": "policies/default_policies.yaml",
        "evaluation_timeout": 5.0,
        "cache_policies": True
    })
    
    # Tool Registry
    tool_registry: Dict[str, Any] = field(default_factory=lambda: {
        "auto_register": True,
        "verification_required": True,
        "attestation_required": True,
        "max_tools_per_agent": 50
    })
    
    # Logging
    logging: Dict[str, Any] = field(default_factory=lambda: {
        "level": "INFO",
        "audit_logging": True,
        "security_events": True,
        "log_file": "logs/security.log",
        "audit_file": "logs/audit.log"
    })
    
    # Cryptography
    cryptography: Dict[str, Any] = field(default_factory=lambda: {
        "key_size": 2048,
        "hash_algorithm": "SHA256",
        "signature_algorithm": "RSA-PSS",
        "encryption_algorithm": "AES-256-GCM"
    })
    
    # MAS Adapters
    mas_adapters: Dict[str, Any] = field(default_factory=lambda: {
        "langgraph": {
            "enabled": True,
            "workflow_security": True,
            "node_verification": True
        },
        "autogen": {
            "enabled": True,
            "conversation_security": True,
            "message_encryption": True
        },
        "crewai": {
            "enabled": True,
            "crew_verification": True,
            "task_security": True
        }
    })
    
    # Performance
    performance: Dict[str, Any] = field(default_factory=lambda: {
        "max_concurrent_operations": 100,
        "operation_timeout": 30.0,
        "cache_size": 1000,
        "cleanup_interval": 3600
    })
    
    # Security
    security: Dict[str, Any] = field(default_factory=lambda: {
        "rate_limiting": {
            "enabled": True,
            "max_requests_per_minute": 100,
            "max_requests_per_hour": 1000
        },
        "threat_detection": {
            "enabled": True,
            "anomaly_detection": True,
            "pattern_analysis": True
        },
        "monitoring": {
            "enabled": True,
            "metrics_collection": True,
            "alert_threshold": 0.8
        }
    })


def load_config(config_path: Optional[str] = None) -> SecurityConfig:
    """
    Load security configuration from file or environment
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Security configuration object
    """
    config = SecurityConfig()
    
    # Try to load from file
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    file_config = yaml.safe_load(f)
                elif config_path.endswith('.json'):
                    file_config = json.load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {config_path}")
            
            # Update config with file values
            config = _update_config_from_dict(config, file_config)
            
        except Exception as e:
            print(f"Warning: Failed to load config file {config_path}: {e}")
    
    # Override with environment variables
    config = _update_config_from_env(config)
    
    return config


def _update_config_from_dict(config: SecurityConfig, config_dict: Dict[str, Any]) -> SecurityConfig:
    """Update config object from dictionary"""
    for section, values in config_dict.items():
        if hasattr(config, section) and isinstance(values, dict):
            current_section = getattr(config, section)
            current_section.update(values)
            setattr(config, section, current_section)
    
    return config


def _update_config_from_env(config: SecurityConfig) -> SecurityConfig:
    """Update config object from environment variables"""
    env_mappings = {
        # Identity Management
        "MCP_SECURITY_REQUIRE_AUTH": ("identity_management", "require_authentication", bool),
        "MCP_SECURITY_SESSION_TIMEOUT": ("identity_management", "session_timeout", int),
        
        # Trust Calculation
        "MCP_SECURITY_DECAY_FACTOR": ("trust_calculation", "decay_factor", float),
        "MCP_SECURITY_SYBIL_THRESHOLD": ("trust_calculation", "sybil_threshold", float),
        
        # MCP Integration
        "MCP_SECURITY_TOOL_VERIFICATION": ("mcp_integration", "tool_verification", "enabled", bool),
        "MCP_SECURITY_AUTO_DISCOVER": ("mcp_integration", "discovery", "auto_discover", bool),
        
        # Logging
        "MCP_SECURITY_LOG_LEVEL": ("logging", "level", str),
        "MCP_SECURITY_AUDIT_LOGGING": ("logging", "audit_logging", bool),
        
        # Performance
        "MCP_SECURITY_MAX_CONCURRENT": ("performance", "max_concurrent_operations", int),
        "MCP_SECURITY_OPERATION_TIMEOUT": ("performance", "operation_timeout", float),
        
        # Security
        "MCP_SECURITY_RATE_LIMITING": ("security", "rate_limiting", "enabled", bool),
        "MCP_SECURITY_THREAT_DETECTION": ("security", "threat_detection", "enabled", bool)
    }
    
    for env_var, (section, *keys, value_type) in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            try:
                # Convert value to appropriate type
                if value_type == bool:
                    converted_value = env_value.lower() in ('true', '1', 'yes', 'on')
                elif value_type == int:
                    converted_value = int(env_value)
                elif value_type == float:
                    converted_value = float(env_value)
                else:
                    converted_value = env_value
                
                # Set nested value
                current_section = getattr(config, section)
                if len(keys) == 1:
                    current_section[keys[0]] = converted_value
                elif len(keys) == 2:
                    if keys[0] not in current_section:
                        current_section[keys[0]] = {}
                    current_section[keys[0]][keys[1]] = converted_value
                
            except (ValueError, TypeError) as e:
                print(f"Warning: Invalid environment variable {env_var}: {e}")
    
    return config


def save_config(config: SecurityConfig, config_path: str) -> bool:
    """
    Save security configuration to file
    
    Args:
        config: Security configuration object
        config_path: Path to save configuration file
        
    Returns:
        True if save successful
    """
    try:
        # Convert config to dictionary
        config_dict = {
            "identity_management": config.identity_management,
            "trust_calculation": config.trust_calculation,
            "mcp_integration": config.mcp_integration,
            "policy_engine": config.policy_engine,
            "tool_registry": config.tool_registry,
            "logging": config.logging,
            "cryptography": config.cryptography,
            "mas_adapters": config.mas_adapters,
            "performance": config.performance,
            "security": config.security
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        # Save to file
        with open(config_path, 'w') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            elif config_path.endswith('.json'):
                json.dump(config_dict, f, indent=2)
            else:
                raise ValueError(f"Unsupported config file format: {config_path}")
        
        return True
        
    except Exception as e:
        print(f"Error saving config: {e}")
        return False


def validate_config(config: SecurityConfig) -> List[str]:
    """
    Validate security configuration
    
    Args:
        config: Security configuration object
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Validate identity management
    if not isinstance(config.identity_management.get("session_timeout"), (int, float)):
        errors.append("session_timeout must be a number")
    
    if config.identity_management.get("session_timeout", 0) <= 0:
        errors.append("session_timeout must be positive")
    
    # Validate trust calculation
    decay_factor = config.trust_calculation.get("decay_factor", 0)
    if not 0 < decay_factor < 1:
        errors.append("decay_factor must be between 0 and 1")
    
    min_events = config.trust_calculation.get("min_events", 0)
    if not isinstance(min_events, int) or min_events < 1:
        errors.append("min_events must be a positive integer")
    
    # Validate performance settings
    max_concurrent = config.performance.get("max_concurrent_operations", 0)
    if not isinstance(max_concurrent, int) or max_concurrent < 1:
        errors.append("max_concurrent_operations must be a positive integer")
    
    operation_timeout = config.performance.get("operation_timeout", 0)
    if not isinstance(operation_timeout, (int, float)) or operation_timeout <= 0:
        errors.append("operation_timeout must be a positive number")
    
    # Validate cryptography settings
    key_size = config.cryptography.get("key_size", 0)
    if key_size not in [1024, 2048, 3072, 4096]:
        errors.append("key_size must be 1024, 2048, 3072, or 4096")
    
    # Validate logging settings
    log_level = config.logging.get("level", "")
    if log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        errors.append("log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    
    return errors


def get_default_config_path() -> str:
    """
    Get default configuration file path
    
    Returns:
        Default configuration file path
    """
    # Try to find config in common locations
    possible_paths = [
        "config/security_config.yaml",
        "security_config.yaml",
        os.path.expanduser("~/.mcp_security/config.yaml"),
        "/etc/mcp_security/config.yaml"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Return default path
    return "config/security_config.yaml"
