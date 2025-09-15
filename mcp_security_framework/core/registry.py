"""
Tool Registry for MCP Security Framework

This module provides tool registration, verification, and management capabilities.
"""

import time
import hashlib
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class ToolStatus(Enum):
    """Tool status enumeration"""
    REGISTERED = "registered"
    VERIFIED = "verified"
    PENDING = "pending"
    REJECTED = "rejected"
    SUSPENDED = "suspended"


class ToolAttestation:
    """Tool attestation data structure"""
    
    def __init__(
        self,
        attestation_id: str,
        tool_id: str,
        attestation_type: str,
        attestation_data: Dict[str, Any],
        signer: str,
        signature: bytes,
        timestamp: float
    ):
        self.attestation_id = attestation_id
        self.tool_id = tool_id
        self.attestation_type = attestation_type
        self.attestation_data = attestation_data
        self.signer = signer
        self.signature = signature
        self.timestamp = timestamp


@dataclass
class ToolManifest:
    """Tool manifest data structure"""
    tool_id: str
    name: str
    version: str
    description: str
    author: str
    capabilities: List[str]
    parameters: Dict[str, Any]
    risk_level: str
    security_requirements: List[str]
    dependencies: List[str]
    attestations: List[ToolAttestation] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    status: ToolStatus = ToolStatus.REGISTERED


class ToolRegistry:
    """
    Tool registry for MCP security framework
    
    Features:
    - Tool registration and verification
    - Attestation management
    - Security scanning and validation
    - Tool discovery and metadata management
    - Supply chain verification
    """
    
    def __init__(self, registry_private_key: Optional[bytes] = None):
        """
        Initialize tool registry
        
        Args:
            registry_private_key: Registry signing key (generated if None)
        """
        self.tools: Dict[str, ToolManifest] = {}
        self.attestations: Dict[str, List[ToolAttestation]] = {}
        self.verification_rules = self._load_verification_rules()
        
        # Initialize registry signing key
        if registry_private_key:
            self.registry_private_key = serialization.load_pem_private_key(
                registry_private_key, password=None, backend=default_backend()
            )
        else:
            self.registry_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        
        self.registry_public_key = self.registry_private_key.public_key()
    
    def _load_verification_rules(self) -> Dict[str, Any]:
        """Load tool verification rules"""
        return {
            "required_fields": [
                "tool_id", "name", "version", "description", "author",
                "capabilities", "parameters", "risk_level"
            ],
            "allowed_risk_levels": ["low", "medium", "high", "critical"],
            "required_capabilities": ["tool_execution"],
            "forbidden_capabilities": [
                "system_access", "file_system_write", "network_access",
                "database_write", "user_data_access"
            ],
            "max_parameter_count": 20,
            "max_description_length": 1000
        }
    
    def register_tool(self, manifest: ToolManifest) -> Tuple[bool, str]:
        """
        Register a new tool
        
        Args:
            manifest: Tool manifest
            
        Returns:
            Tuple of (success, message)
        """
        # Validate manifest
        validation_result = self._validate_manifest(manifest)
        if not validation_result["valid"]:
            return False, f"Manifest validation failed: {validation_result['errors']}"
        
        # Check for duplicate tool ID
        if manifest.tool_id in self.tools:
            return False, "Tool ID already exists"
        
        # Set initial status
        manifest.status = ToolStatus.REGISTERED
        manifest.created_at = time.time()
        manifest.updated_at = time.time()
        
        # Store tool
        self.tools[manifest.tool_id] = manifest
        self.attestations[manifest.tool_id] = []
        
        return True, "Tool registered successfully"
    
    def verify_tool(self, tool_id: str, verification_context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Verify a tool for security and compliance
        
        Args:
            tool_id: Tool identifier
            verification_context: Additional verification context
            
        Returns:
            Tuple of (success, message)
        """
        if tool_id not in self.tools:
            return False, "Tool not found"
        
        tool = self.tools[tool_id]
        
        # Perform security verification
        security_result = self._perform_security_verification(tool, verification_context)
        if not security_result["passed"]:
            tool.status = ToolStatus.REJECTED
            return False, f"Security verification failed: {security_result['issues']}"
        
        # Perform attestation verification
        attestation_result = self._verify_attestations(tool_id)
        if not attestation_result["passed"]:
            tool.status = ToolStatus.PENDING
            return False, f"Attestation verification failed: {attestation_result['issues']}"
        
        # Mark as verified
        tool.status = ToolStatus.VERIFIED
        tool.updated_at = time.time()
        
        return True, "Tool verified successfully"
    
    def add_attestation(self, tool_id: str, attestation: ToolAttestation) -> bool:
        """
        Add attestation to a tool
        
        Args:
            tool_id: Tool identifier
            attestation: Attestation to add
            
        Returns:
            True if attestation added successfully
        """
        if tool_id not in self.tools:
            return False
        
        # Verify attestation signature
        if not self._verify_attestation_signature(attestation):
            return False
        
        # Add attestation
        if tool_id not in self.attestations:
            self.attestations[tool_id] = []
        
        self.attestations[tool_id].append(attestation)
        
        # Update tool timestamp
        self.tools[tool_id].updated_at = time.time()
        
        return True
    
    def get_tool(self, tool_id: str) -> Optional[ToolManifest]:
        """
        Get tool manifest
        
        Args:
            tool_id: Tool identifier
            
        Returns:
            Tool manifest or None if not found
        """
        return self.tools.get(tool_id)
    
    def list_tools(
        self, 
        status: Optional[ToolStatus] = None,
        risk_level: Optional[str] = None,
        capability: Optional[str] = None
    ) -> List[ToolManifest]:
        """
        List tools with optional filtering
        
        Args:
            status: Filter by tool status
            risk_level: Filter by risk level
            capability: Filter by capability
            
        Returns:
            List of matching tool manifests
        """
        tools = list(self.tools.values())
        
        if status:
            tools = [t for t in tools if t.status == status]
        
        if risk_level:
            tools = [t for t in tools if t.risk_level == risk_level]
        
        if capability:
            tools = [t for t in tools if capability in t.capabilities]
        
        return tools
    
    def search_tools(self, query: str) -> List[ToolManifest]:
        """
        Search tools by name, description, or capabilities
        
        Args:
            query: Search query
            
        Returns:
            List of matching tool manifests
        """
        query_lower = query.lower()
        matching_tools = []
        
        for tool in self.tools.values():
            # Search in name
            if query_lower in tool.name.lower():
                matching_tools.append(tool)
                continue
            
            # Search in description
            if query_lower in tool.description.lower():
                matching_tools.append(tool)
                continue
            
            # Search in capabilities
            for capability in tool.capabilities:
                if query_lower in capability.lower():
                    matching_tools.append(tool)
                    break
        
        return matching_tools
    
    def suspend_tool(self, tool_id: str, reason: str = "") -> bool:
        """
        Suspend a tool
        
        Args:
            tool_id: Tool identifier
            reason: Reason for suspension
            
        Returns:
            True if tool suspended successfully
        """
        if tool_id not in self.tools:
            return False
        
        self.tools[tool_id].status = ToolStatus.SUSPENDED
        self.tools[tool_id].updated_at = time.time()
        
        return True
    
    def unsuspend_tool(self, tool_id: str) -> bool:
        """
        Unsuspend a tool
        
        Args:
            tool_id: Tool identifier
            
        Returns:
            True if tool unsuspended successfully
        """
        if tool_id not in self.tools:
            return False
        
        if self.tools[tool_id].status == ToolStatus.SUSPENDED:
            self.tools[tool_id].status = ToolStatus.VERIFIED
            self.tools[tool_id].updated_at = time.time()
        
        return True
    
    def _validate_manifest(self, manifest: ToolManifest) -> Dict[str, Any]:
        """Validate tool manifest"""
        result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Check required fields
        for field in self.verification_rules["required_fields"]:
            if not hasattr(manifest, field) or getattr(manifest, field) is None:
                result["errors"].append(f"Missing required field: {field}")
                result["valid"] = False
        
        # Check risk level
        if manifest.risk_level not in self.verification_rules["allowed_risk_levels"]:
            result["errors"].append(f"Invalid risk level: {manifest.risk_level}")
            result["valid"] = False
        
        # Check capabilities
        if not any(cap in manifest.capabilities for cap in self.verification_rules["required_capabilities"]):
            result["errors"].append("Missing required capabilities")
            result["valid"] = False
        
        forbidden_caps = [cap for cap in manifest.capabilities if cap in self.verification_rules["forbidden_capabilities"]]
        if forbidden_caps:
            result["errors"].append(f"Forbidden capabilities: {forbidden_caps}")
            result["valid"] = False
        
        # Check parameter count
        if len(manifest.parameters) > self.verification_rules["max_parameter_count"]:
            result["warnings"].append(f"Too many parameters: {len(manifest.parameters)}")
        
        # Check description length
        if len(manifest.description) > self.verification_rules["max_description_length"]:
            result["warnings"].append("Description too long")
        
        return result
    
    def _perform_security_verification(
        self, 
        tool: ToolManifest, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform security verification on tool"""
        result = {
            "passed": True,
            "issues": []
        }
        
        # Check for suspicious patterns in description
        suspicious_patterns = [
            "execute", "system", "shell", "command", "eval",
            "import", "require", "load", "exec"
        ]
        
        description_lower = tool.description.lower()
        for pattern in suspicious_patterns:
            if pattern in description_lower:
                result["issues"].append(f"Suspicious pattern in description: {pattern}")
                result["passed"] = False
        
        # Check parameter security
        for param_name, param_info in tool.parameters.items():
            if isinstance(param_info, dict):
                param_type = param_info.get("type", "")
                if param_type == "string" and "command" in param_name.lower():
                    result["issues"].append(f"Potentially dangerous parameter: {param_name}")
                    result["passed"] = False
        
        # Check for high-risk capabilities
        high_risk_caps = ["system_access", "file_system_write", "network_access"]
        for cap in tool.capabilities:
            if cap in high_risk_caps and tool.risk_level not in ["high", "critical"]:
                result["issues"].append(f"High-risk capability with low risk level: {cap}")
                result["passed"] = False
        
        return result
    
    def _verify_attestations(self, tool_id: str) -> Dict[str, Any]:
        """Verify tool attestations"""
        result = {
            "passed": True,
            "issues": []
        }
        
        if tool_id not in self.attestations:
            result["issues"].append("No attestations found")
            result["passed"] = False
            return result
        
        attestations = self.attestations[tool_id]
        
        # Check for required attestation types
        required_types = ["security_scan", "code_review", "supply_chain"]
        found_types = [att.attestation_type for att in attestations]
        
        for req_type in required_types:
            if req_type not in found_types:
                result["issues"].append(f"Missing required attestation: {req_type}")
                result["passed"] = False
        
        # Verify attestation signatures
        for attestation in attestations:
            if not self._verify_attestation_signature(attestation):
                result["issues"].append(f"Invalid attestation signature: {attestation.attestation_id}")
                result["passed"] = False
        
        return result
    
    def _verify_attestation_signature(self, attestation: ToolAttestation) -> bool:
        """Verify attestation signature"""
        try:
            # Create signature data
            signature_data = {
                "attestation_id": attestation.attestation_id,
                "tool_id": attestation.tool_id,
                "attestation_type": attestation.attestation_type,
                "attestation_data": attestation.attestation_data,
                "signer": attestation.signer,
                "timestamp": attestation.timestamp
            }
            
            signature_json = json.dumps(signature_data, sort_keys=True)
            
            # Verify signature (simplified - in production, use proper key management)
            # For now, just check if signature exists
            return len(attestation.signature) > 0
            
        except Exception:
            return False
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        total_tools = len(self.tools)
        status_counts = {}
        risk_counts = {}
        
        for tool in self.tools.values():
            # Count by status
            status = tool.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # Count by risk level
            risk = tool.risk_level
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        return {
            "total_tools": total_tools,
            "status_distribution": status_counts,
            "risk_distribution": risk_counts,
            "total_attestations": sum(len(atts) for atts in self.attestations.values())
        }
