"""
Enhanced MCP Security Gateway

Provides inference-time security including context sanitization
and toolchain anomaly detection.
"""

import time
import logging
from typing import Dict, List, Optional, Any, Tuple

from .gateway import MCPSecurityGateway, RequestContext, ResponseContext
from .identity import IdentityManager
from .trust import TrustCalculator
from .policy import PolicyEngine, PolicyContext, PolicyDecision
from .registry import ToolRegistry

from ..security.sanitization import PayloadSanitizer
from ..security.advanced.advanced_behavioral_analysis import InferenceSafetyAnalyzer


class EnhancedMCPSecurityGateway(MCPSecurityGateway):
    """
    Enterprise-ready Security Gateway.
    
    Integrates Payload Sanitization and Inference Safety Analysis
    to protect against indirect prompt injections and parasitic toolchains.
    """
    
    def __init__(
        self,
        identity_manager: IdentityManager = None,
        trust_calculator: TrustCalculator = None,
        policy_engine: PolicyEngine = None,
        tool_registry: ToolRegistry = None,
        **kwargs
    ):
        super().__init__(
            identity_manager=identity_manager,
            trust_calculator=trust_calculator,
            policy_engine=policy_engine,
            tool_registry=tool_registry,
            **kwargs
        )
        
        self.sanitizer = PayloadSanitizer()
        self.inference_analyzer = InferenceSafetyAnalyzer()
        self.logger = logging.getLogger(__name__)
        self.oauth_config = self._load_oauth_config()
        self.sanitization_config = self._load_sanitization_config()
        if self.identity_manager and hasattr(self.identity_manager, "oauth_config"):
            if not self.identity_manager.oauth_config:
                self.identity_manager.oauth_config = self.oauth_config
        
    async def process_request(self, agent_id: str, request: RequestContext) -> ResponseContext:
        """
        Process request with sanitization and safety analysis.
        """
        try:
            # 0. Strict OAuth 2.1 validation (resource server)
            auth_required = bool(self.config.get("identity_management", {}).get("require_authentication", True))
            if auth_required:
                token = request.metadata.get("auth_token") if request.metadata else None
                token_result = self._validate_oauth_token(token, request)
                if not token_result[0]:
                    return ResponseContext(
                        status="blocked",
                        message=f"Request blocked: {token_result[1]}",
                        security_assessment={"reason": token_result[1]}
                    )
                if token_result[2] and token_result[2] != agent_id:
                    return ResponseContext(
                        status="blocked",
                        message="Request blocked: agent_id token mismatch",
                        security_assessment={"reason": "agent_id_mismatch"}
                    )

            # 1. Sanitize incoming parameters to prevent indirect prompt injection
            if request.metadata and "parameters" in request.metadata:
                sanitized = self.sanitizer.sanitize_payload_with_report(
                    request.metadata["parameters"]
                )
                request.metadata["parameters"] = sanitized["payload"]
                if self._should_block_sanitization(sanitized):
                    return ResponseContext(
                        status="blocked",
                        message="Request blocked due to prompt injection indicators",
                        security_assessment={
                            "reason": "prompt_injection_indicators",
                            "redactions": sanitized["redactions"],
                            "matches": sanitized["matches"]
                        }
                    )
                
            # 2. Check for parasitic toolchains and inference anomalies
            tool_id = request.resource

            # 1b. Tool manifest integrity check (poisoning defense)
            integrity_ok, integrity_reason = self._verify_tool_manifest_integrity(tool_id)
            if not integrity_ok:
                return ResponseContext(
                    status="blocked",
                    message="Request blocked due to tool metadata integrity failure",
                    security_assessment={"reason": integrity_reason}
                )
            
            # Basic risk classification stub
            risk_level = self._resolve_tool_risk_level(tool_id)
                
            is_safe, reason = self.inference_analyzer.check_safety(agent_id, tool_id, risk_level)
            
            if not is_safe:
                self.logger.warning(f"Safety check failed for {agent_id}: {reason}")
                return ResponseContext(
                    status="blocked",
                    message=f"Request blocked due to safety concerns: {reason}",
                    security_assessment={"reason": reason}
                )
                
            # 3. Log execution for future tracking
            self.inference_analyzer.log_execution(
                agent_id, 
                tool_id, 
                request.metadata.get("parameters", {}),
                risk_level
            )

            # 3b. Policy enforcement (RBAC/ABAC/CBAC)
            policy_decision = self._evaluate_policy(agent_id, tool_id, risk_level, request)
            if policy_decision == PolicyDecision.DENY:
                return ResponseContext(
                    status="blocked",
                    message="Request blocked by policy",
                    security_assessment={"reason": "policy_denied"}
                )
            
            # 4. Proceed with base gateway processing
            response = await super().process_request(agent_id, request)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing enhanced request: {e}")
            return ResponseContext(
                status="error",
                message=f"Enhanced processing failed: {str(e)}"
            )

    def _load_oauth_config(self) -> Dict[str, Any]:
        security_cfg = self.config.get("security", {})
        return security_cfg.get("oauth", {})

    def _load_sanitization_config(self) -> Dict[str, Any]:
        security_cfg = self.config.get("security", {})
        return security_cfg.get("sanitization", {})

    def _validate_oauth_token(
        self,
        token: Optional[str],
        request: RequestContext
    ) -> Tuple[bool, str, Optional[str]]:
        if not self.identity_manager:
            return False, "identity_manager_missing", None

        expected_audience = self.oauth_config.get("expected_audience")
        expected_issuer = self.oauth_config.get("expected_issuer")
        required_scopes = self.oauth_config.get("required_scopes", [])
        resource = self.oauth_config.get("resource")

        result = self.identity_manager.validate_access_token(
            token=token,
            expected_audience=expected_audience,
            expected_issuer=expected_issuer,
            required_scopes=required_scopes,
            resource=resource
        )
        if not result.valid:
            return False, result.reason, None

        return True, "ok", result.agent_id

    def _should_block_sanitization(self, sanitized: Dict[str, Any]) -> bool:
        max_redactions = int(self.sanitization_config.get("max_redactions", 0))
        block_on_redaction = bool(self.sanitization_config.get("block_on_redaction", False))
        if not block_on_redaction:
            return False
        return sanitized.get("redactions", 0) > max_redactions

    def _resolve_tool_risk_level(self, tool_id: str) -> str:
        if self.tool_registry:
            manifest = self.tool_registry.get_tool(tool_id)
            if manifest and manifest.risk_level:
                return manifest.risk_level
        tool = self.verified_tools.get(tool_id)
        if tool and tool.risk_level:
            return tool.risk_level.value if hasattr(tool.risk_level, "value") else str(tool.risk_level)

        if "write" in tool_id or "delete" in tool_id or "execute" in tool_id:
            return "high"
        return "low"

    def _verify_tool_manifest_integrity(self, tool_id: str) -> Tuple[bool, str]:
        if not self.tool_registry:
            return True, "tool_registry_not_configured"

        if tool_id not in self.tool_registry.tools:
            return False, "tool_not_registered"

        tool = self.verified_tools.get(tool_id)
        if not tool:
            return False, "tool_not_verified"

        runtime_metadata = {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters
        }
        return self.tool_registry.verify_tool_runtime_metadata(tool_id, runtime_metadata)

    def _evaluate_policy(
        self,
        agent_id: str,
        tool_id: str,
        risk_level: str,
        request: RequestContext
    ) -> PolicyDecision:
        if not self.policy_engine:
            return PolicyDecision.ALLOW

        identity = self.identity_manager.get_agent_identity(agent_id) if self.identity_manager else None
        agent_type = identity.agent_type.value if identity else "unknown"
        capabilities = identity.capabilities if identity else []
        trust_score = identity.trust_score if identity else 0.5

        if self.trust_calculator:
            trust = self.trust_calculator.get_trust_score(agent_id)
            if trust:
                trust_score = trust.overall_score

        policy_context = PolicyContext(
            agent_id=agent_id,
            agent_type=agent_type,
            agent_capabilities=capabilities,
            agent_trust_score=trust_score,
            tool_id=tool_id,
            tool_risk_level=risk_level,
            operation=request.operation,
            parameters=request.metadata.get("parameters", {}) if request.metadata else {},
            context_metadata=request.metadata or {}
        )
        return self.policy_engine.evaluate_access(policy_context)