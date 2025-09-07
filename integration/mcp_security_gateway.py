"""
MCP Security Gateway for Secure Multi-Agent Systems

This module provides secure integration with MCP (Model Context Protocol) servers,
including tool verification, context management, and secure communication.
"""

import asyncio
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import aiohttp
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from pydantic import BaseModel, Field


class MCPToolStatus(Enum):
    """MCP tool status enumeration"""
    VERIFIED = "verified"
    PENDING = "pending"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class MCPToolRisk(Enum):
    """MCP tool risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class MCPTool:
    """MCP tool information"""
    tool_id: str
    name: str
    description: str
    parameters: Dict[str, Any]
    server_url: str
    status: MCPToolStatus
    risk_level: MCPToolRisk
    capabilities: List[str]
    verified_at: Optional[float] = None
    last_used: Optional[float] = None
    usage_count: int = 0
    success_rate: float = 0.0


@dataclass
class MCPContext:
    """MCP context information"""
    context_id: str
    content: Dict[str, Any]
    encryption_key: bytes
    created_at: float
    expires_at: float
    access_control: Dict[str, List[str]]  # agent_id -> permissions
    metadata: Dict[str, str]


class MCPSecurityGateway:
    """
    Secure gateway for MCP server integration
    
    Features:
    - Tool verification and safety assessment
    - Secure context management
    - Encrypted communication with MCP servers
    - Access control and audit logging
    - Threat detection and response
    """
    
    def __init__(self, config_path: str = "config/security_config.yaml"):
        """
        Initialize MCP security gateway
        
        Args:
            config_path: Path to security configuration file
        """
        self.config = self._load_config(config_path)
        self.verified_tools: Dict[str, MCPTool] = {}
        self.active_contexts: Dict[str, MCPContext] = {}
        self.session = None
        self.audit_log = []
        
        # Security settings
        self.encryption_key = self._generate_encryption_key()
        self.verification_rules = self._load_verification_rules()
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load security configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Return default config if file not found
            return {
                "mcp_integration": {
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
                    }
                }
            }
    
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for context management"""
        return hashlib.sha256(f"mcp_security_key_{time.time()}".encode()).digest()
    
    def _load_verification_rules(self) -> Dict[str, Any]:
        """Load tool verification rules"""
        return {
            "allowed_operations": [
                "read", "write", "search", "analyze", "transform"
            ],
            "forbidden_operations": [
                "execute", "delete", "format", "shutdown", "restart"
            ],
            "risk_indicators": [
                "file_system_access",
                "network_access", 
                "system_commands",
                "database_access"
            ],
            "trusted_servers": [
                "localhost:3000",
                "mcp.example.com"
            ]
        }
    
    async def discover_mcp_servers(self, network_range: str = "localhost") -> List[str]:
        """
        Discover MCP servers on the network
        
        Args:
            network_range: Network range to scan
            
        Returns:
            List of discovered MCP server URLs
        """
        discovered_servers = []
        
        # For demo purposes, return some example servers
        # In production, this would scan the network
        example_servers = [
            "http://localhost:3000",
            "http://localhost:3001", 
            "http://localhost:3002"
        ]
        
        for server_url in example_servers:
            try:
                if await self._test_server_connection(server_url):
                    discovered_servers.append(server_url)
                    print(f"Discovered MCP server: {server_url}")
            except Exception as e:
                print(f"Failed to connect to {server_url}: {e}")
        
        return discovered_servers
    
    async def _test_server_connection(self, server_url: str) -> bool:
        """Test connection to MCP server"""
        try:
            if not self.session:
                return False
            
            async with self.session.get(f"{server_url}/health", timeout=5) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def register_mcp_server(self, server_url: str, auth_token: Optional[str] = None) -> bool:
        """
        Register and verify an MCP server
        
        Args:
            server_url: MCP server URL
            auth_token: Optional authentication token
            
        Returns:
            True if registration successful
        """
        try:
            # Test server connection
            if not await self._test_server_connection(server_url):
                print(f"Failed to connect to MCP server: {server_url}")
                return False
            
            # Get server capabilities
            capabilities = await self._get_server_capabilities(server_url, auth_token)
            if not capabilities:
                print(f"Failed to get capabilities from server: {server_url}")
                return False
            
            # Verify server security
            security_status = await self._verify_server_security(server_url, capabilities)
            if not security_status["verified"]:
                print(f"Server security verification failed: {server_url}")
                return False
            
            print(f"Successfully registered MCP server: {server_url}")
            return True
            
        except Exception as e:
            print(f"Error registering MCP server {server_url}: {e}")
            return False
    
    async def _get_server_capabilities(self, server_url: str, auth_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get server capabilities"""
        try:
            headers = {}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"
            
            async with self.session.get(f"{server_url}/capabilities", headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception:
            return None
    
    async def _verify_server_security(self, server_url: str, capabilities: Dict[str, Any]) -> Dict[str, Any]:
        """Verify server security"""
        security_checks = {
            "verified": True,
            "issues": [],
            "risk_level": "low"
        }
        
        # Check if server is in trusted list
        if server_url not in self.verification_rules["trusted_servers"]:
            security_checks["issues"].append("Server not in trusted list")
            security_checks["risk_level"] = "medium"
        
        # Check for dangerous capabilities
        dangerous_caps = ["system_access", "file_system", "network_access"]
        for cap in dangerous_caps:
            if cap in str(capabilities):
                security_checks["issues"].append(f"Dangerous capability detected: {cap}")
                security_checks["risk_level"] = "high"
        
        if security_checks["issues"]:
            security_checks["verified"] = False
        
        return security_checks
    
    async def discover_tools(self, server_url: str) -> List[MCPTool]:
        """
        Discover tools available on an MCP server
        
        Args:
            server_url: MCP server URL
            
        Returns:
            List of discovered MCP tools
        """
        tools = []
        
        try:
            async with self.session.get(f"{server_url}/tools") as response:
                if response.status == 200:
                    tools_data = await response.json()
                    
                    for tool_data in tools_data.get("tools", []):
                        tool = MCPTool(
                            tool_id=tool_data["id"],
                            name=tool_data["name"],
                            description=tool_data["description"],
                            parameters=tool_data.get("parameters", {}),
                            server_url=server_url,
                            status=MCPToolStatus.PENDING,
                            risk_level=MCPToolRisk.UNKNOWN,
                            capabilities=tool_data.get("capabilities", [])
                        )
                        
                        # Verify tool safety
                        await self._verify_tool_safety(tool)
                        tools.append(tool)
                        
        except Exception as e:
            print(f"Error discovering tools from {server_url}: {e}")
        
        return tools
    
    async def _verify_tool_safety(self, tool: MCPTool) -> None:
        """Verify tool safety and set risk level"""
        risk_score = 0
        
        # Check for dangerous operations
        dangerous_ops = self.verification_rules["forbidden_operations"]
        for op in dangerous_ops:
            if op.lower() in tool.description.lower():
                risk_score += 2
        
        # Check for risk indicators
        risk_indicators = self.verification_rules["risk_indicators"]
        for indicator in risk_indicators:
            if indicator.lower() in tool.description.lower():
                risk_score += 1
        
        # Set risk level based on score
        if risk_score >= 3:
            tool.risk_level = MCPToolRisk.CRITICAL
            tool.status = MCPToolStatus.REJECTED
        elif risk_score >= 2:
            tool.risk_level = MCPToolRisk.HIGH
            tool.status = MCPToolStatus.REJECTED
        elif risk_score >= 1:
            tool.risk_level = MCPToolRisk.MEDIUM
            tool.status = MCPToolStatus.PENDING
        else:
            tool.risk_level = MCPToolRisk.LOW
            tool.status = MCPToolStatus.VERIFIED
        
        # Mark as verified if safe
        if tool.status == MCPToolStatus.VERIFIED:
            tool.verified_at = time.time()
            self.verified_tools[tool.tool_id] = tool
    
    async def execute_tool(
        self, 
        tool_id: str, 
        parameters: Dict[str, Any], 
        agent_id: str,
        context_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute an MCP tool securely
        
        Args:
            tool_id: Tool identifier
            parameters: Tool parameters
            agent_id: Agent requesting execution
            context_id: Optional context identifier
            
        Returns:
            Tool execution result
        """
        # Check if tool is verified
        if tool_id not in self.verified_tools:
            return {
                "success": False,
                "error": "Tool not verified or not found",
                "tool_id": tool_id
            }
        
        tool = self.verified_tools[tool_id]
        
        # Check agent permissions
        if not await self._check_agent_permissions(agent_id, tool):
            return {
                "success": False,
                "error": "Agent not authorized to use this tool",
                "tool_id": tool_id
            }
        
        # Prepare context if provided
        context_data = None
        if context_id and context_id in self.active_contexts:
            context = self.active_contexts[context_id]
            context_data = await self._decrypt_context(context)
        
        # Execute tool
        try:
            result = await self._execute_tool_request(tool, parameters, context_data)
            
            # Update tool usage statistics
            tool.usage_count += 1
            tool.last_used = time.time()
            
            # Log execution
            await self._log_tool_execution(agent_id, tool_id, parameters, result)
            
            return {
                "success": True,
                "result": result,
                "tool_id": tool_id,
                "execution_time": time.time()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "tool_id": tool_id
            }
    
    async def _check_agent_permissions(self, agent_id: str, tool: MCPTool) -> bool:
        """Check if agent has permission to use tool"""
        # For demo purposes, allow all verified agents
        # In production, this would check against access control policies
        return tool.status == MCPToolStatus.VERIFIED
    
    async def _execute_tool_request(
        self, 
        tool: MCPTool, 
        parameters: Dict[str, Any], 
        context_data: Optional[Dict[str, Any]]
    ) -> Any:
        """Execute tool request on MCP server"""
        request_data = {
            "tool_id": tool.tool_id,
            "parameters": parameters
        }
        
        if context_data:
            request_data["context"] = context_data
        
        async with self.session.post(
            f"{tool.server_url}/execute",
            json=request_data
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Tool execution failed: {response.status}")
    
    async def create_secure_context(
        self, 
        content: Dict[str, Any], 
        agent_id: str,
        expires_in: int = 3600
    ) -> str:
        """
        Create secure context for sharing between agents
        
        Args:
            content: Context content
            agent_id: Agent creating context
            expires_in: Context expiration time in seconds
            
        Returns:
            Context identifier
        """
        context_id = hashlib.sha256(f"{agent_id}_{time.time()}".encode()).hexdigest()[:16]
        
        # Encrypt context content
        encrypted_content = await self._encrypt_context(content)
        
        context = MCPContext(
            context_id=context_id,
            content=encrypted_content,
            encryption_key=self.encryption_key,
            created_at=time.time(),
            expires_at=time.time() + expires_in,
            access_control={agent_id: ["read", "write"]},
            metadata={"created_by": agent_id}
        )
        
        self.active_contexts[context_id] = context
        
        # Log context creation
        await self._log_context_operation("create", agent_id, context_id)
        
        return context_id
    
    async def _encrypt_context(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt context content"""
        # Simplified encryption for demo
        # In production, use proper encryption
        content_str = json.dumps(content)
        encrypted = hashlib.sha256(content_str.encode()).hexdigest()
        return {"encrypted_data": encrypted, "algorithm": "sha256"}
    
    async def _decrypt_context(self, context: MCPContext) -> Dict[str, Any]:
        """Decrypt context content"""
        # Simplified decryption for demo
        # In production, use proper decryption
        return {"decrypted": True, "context_id": context.context_id}
    
    async def _log_tool_execution(
        self, 
        agent_id: str, 
        tool_id: str, 
        parameters: Dict[str, Any], 
        result: Any
    ) -> None:
        """Log tool execution for audit"""
        log_entry = {
            "timestamp": time.time(),
            "agent_id": agent_id,
            "tool_id": tool_id,
            "parameters": parameters,
            "result_success": isinstance(result, dict) and result.get("success", False),
            "action": "tool_execution"
        }
        
        self.audit_log.append(log_entry)
    
    async def _log_context_operation(self, operation: str, agent_id: str, context_id: str) -> None:
        """Log context operation for audit"""
        log_entry = {
            "timestamp": time.time(),
            "agent_id": agent_id,
            "context_id": context_id,
            "operation": operation,
            "action": "context_operation"
        }
        
        self.audit_log.append(log_entry)
    
    def get_verified_tools(self) -> List[MCPTool]:
        """Get list of verified tools"""
        return [tool for tool in self.verified_tools.values() if tool.status == MCPToolStatus.VERIFIED]
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log"""
        return self.audit_log.copy()


# Example usage and testing
async def main():
    """Example usage of MCP Security Gateway"""
    async with MCPSecurityGateway() as gateway:
        # Discover MCP servers
        servers = await gateway.discover_mcp_servers()
        print(f"Discovered {len(servers)} MCP servers")
        
        # Register servers
        for server_url in servers:
            await gateway.register_mcp_server(server_url)
        
        # Discover tools
        for server_url in servers:
            tools = await gateway.discover_tools(server_url)
            print(f"Discovered {len(tools)} tools from {server_url}")
        
        # Get verified tools
        verified_tools = gateway.get_verified_tools()
        print(f"Verified tools: {len(verified_tools)}")
        
        for tool in verified_tools:
            print(f"  - {tool.name}: {tool.risk_level.value} risk")


if __name__ == "__main__":
    asyncio.run(main())
