"""
Identity Management System for MCP Security Framework

This module provides identity management focused on OAuth 2.1 / JWT tokens.
"""

import time
import json
import base64
import hmac
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

class IdentityStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"

class AgentType(Enum):
    WORKER = "worker"
    COORDINATOR = "coordinator"
    MONITOR = "monitor"
    GATEWAY = "gateway"

@dataclass
class AgentIdentity:
    """Agent identity data structure"""
    agent_id: str
    client_id: str
    agent_type: AgentType
    capabilities: List[str]
    trust_score: float
    status: IdentityStatus
    created_at: float
    last_seen: float
    metadata: Dict[str, str]


@dataclass
class TokenValidationResult:
    """Structured result for access token validation."""
    valid: bool
    agent_id: Optional[str]
    reason: str
    claims: Optional[Dict[str, Any]] = None

class IdentityManager:
    """
    Identity management system for enterprise MCP networks using standard OAuth patterns.
    """
    
    def __init__(self, oauth_config: Optional[Dict[str, Any]] = None):
        self.identities: Dict[str, AgentIdentity] = {}
        self.revoked_tokens: set = set()
        self.oauth_config = oauth_config or {}
        
    def register_agent(
        self,
        agent_id: str,
        client_id: str,
        agent_type: AgentType,
        capabilities: List[str],
        metadata: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, str]:
        """Register a new agent in the system"""
        if agent_id in self.identities:
            return False, "Agent ID already exists"
            
        identity = AgentIdentity(
            agent_id=agent_id,
            client_id=client_id,
            agent_type=agent_type,
            capabilities=capabilities,
            trust_score=0.5,
            status=IdentityStatus.ACTIVE,
            created_at=time.time(),
            last_seen=time.time(),
            metadata=metadata or {}
        )
        self.identities[agent_id] = identity
        return True, "Agent registered successfully"
        
    def verify_token(self, token: str) -> Tuple[bool, Optional[str]]:
        """
        Verify a JWT/OAuth token (Stubbed for enterprise integration).
        In a real implementation, this would validate the signature against an IdP's JWKS,
        check expiration, issuer, audience, and scopes.
        """
        if not token or token in self.revoked_tokens:
            return False, None
            
        # Stub: assuming token format is "agentId.signature"
        parts = token.split(".")
        if len(parts) >= 1:
            agent_id = parts[0]
            if agent_id in self.identities and self.identities[agent_id].status == IdentityStatus.ACTIVE:
                self.identities[agent_id].last_seen = time.time()
                return True, agent_id
        return False, None

    def validate_access_token(
        self,
        token: str,
        expected_audience: Optional[str] = None,
        expected_issuer: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        resource: Optional[str] = None
    ) -> TokenValidationResult:
        """
        Validate an OAuth 2.1 access token for resource-server use.

        This supports HS256 JWTs when a shared secret is provided in config.
        If strict mode is enabled and validation cannot be performed, validation fails.
        """
        if not token:
            return TokenValidationResult(False, None, "missing_token")

        if token in self.revoked_tokens:
            return TokenValidationResult(False, None, "token_revoked")

        strict = bool(self.oauth_config.get("strict", False))
        allow_unsigned = bool(self.oauth_config.get("allow_unsigned_jwt", False))

        jwt_parts = token.split(".")
        if len(jwt_parts) == 3:
            parsed = self._parse_jwt(token)
            if not parsed:
                return TokenValidationResult(False, None, "jwt_parse_failed")

            header, claims, signing_input, signature = parsed
            alg = header.get("alg")
            if alg != "HS256":
                if strict:
                    return TokenValidationResult(False, None, "unsupported_alg")
            else:
                secret = self.oauth_config.get("shared_secret")
                if not secret:
                    if strict and not allow_unsigned:
                        return TokenValidationResult(False, None, "missing_shared_secret")
                else:
                    if not self._verify_hs256(signing_input, signature, secret):
                        return TokenValidationResult(False, None, "signature_invalid")

            now = int(time.time())
            exp = claims.get("exp")
            nbf = claims.get("nbf")
            if exp is not None and now >= int(exp):
                return TokenValidationResult(False, None, "token_expired", claims)
            if nbf is not None and now < int(nbf):
                return TokenValidationResult(False, None, "token_not_yet_valid", claims)

            if expected_issuer and claims.get("iss") != expected_issuer:
                return TokenValidationResult(False, None, "issuer_mismatch", claims)

            if expected_audience:
                aud = claims.get("aud")
                if isinstance(aud, list):
                    if expected_audience not in aud:
                        return TokenValidationResult(False, None, "audience_mismatch", claims)
                elif aud != expected_audience:
                    return TokenValidationResult(False, None, "audience_mismatch", claims)

            if resource:
                resource_claim = claims.get("resource") or claims.get("aud")
                if isinstance(resource_claim, list):
                    if resource not in resource_claim:
                        return TokenValidationResult(False, None, "resource_mismatch", claims)
                elif resource_claim and resource_claim != resource:
                    return TokenValidationResult(False, None, "resource_mismatch", claims)

            if required_scopes:
                scope_claim = claims.get("scope") or claims.get("scp") or ""
                if isinstance(scope_claim, list):
                    scopes = set(scope_claim)
                else:
                    scopes = set(scope_claim.split()) if scope_claim else set()
                if not set(required_scopes).issubset(scopes):
                    return TokenValidationResult(False, None, "insufficient_scope", claims)

            agent_id = claims.get("sub") or claims.get("client_id") or claims.get("agent_id")
            return TokenValidationResult(True, agent_id, "ok", claims)

        if strict:
            return TokenValidationResult(False, None, "non_jwt_token_rejected")

        ok, agent_id = self.verify_token(token)
        return TokenValidationResult(ok, agent_id, "stub_token" if ok else "invalid_stub_token")

    def revoke_token(self, token: str) -> bool:
        self.revoked_tokens.add(token)
        return True
        
    def revoke_identity(self, agent_id: str) -> bool:
        if agent_id in self.identities:
            self.identities[agent_id].status = IdentityStatus.REVOKED
            return True
        return False

    def get_agent_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        return self.identities.get(agent_id)
        
    def update_trust_score(self, agent_id: str, new_score: float) -> bool:
        if agent_id in self.identities and 0.0 <= new_score <= 1.0:
            self.identities[agent_id].trust_score = new_score
            return True
        return False

    def _parse_jwt(self, token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]]:
        try:
            header_b64, claims_b64, signature_b64 = token.split(".")
            header = self._b64url_json_decode(header_b64)
            claims = self._b64url_json_decode(claims_b64)
            if header is None or claims is None:
                return None
            signing_input = f"{header_b64}.{claims_b64}".encode()
            signature = self._b64url_decode(signature_b64)
            return header, claims, signing_input, signature
        except Exception:
            return None

    def _b64url_json_decode(self, value: str) -> Optional[Dict[str, Any]]:
        decoded = self._b64url_decode(value)
        if decoded is None:
            return None
        try:
            return json.loads(decoded.decode("utf-8"))
        except Exception:
            return None

    def _b64url_decode(self, value: str) -> Optional[bytes]:
        try:
            padding = "=" * (-len(value) % 4)
            return base64.urlsafe_b64decode(value + padding)
        except Exception:
            return None

    def _verify_hs256(self, signing_input: bytes, signature: bytes, secret: str) -> bool:
        if not signature:
            return False
        computed = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(computed, signature)
