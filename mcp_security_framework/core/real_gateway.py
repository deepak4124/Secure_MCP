import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from .gateway import MCPSecurityGateway, RequestContext, ResponseContext

# Import real models
try:
    from ..models.real_models import RealSecurityModel, RealTrustModel
    REAL_MODELS_AVAILABLE = True
except ImportError:
    REAL_MODELS_AVAILABLE = False

class RealMCPSecurityGateway(MCPSecurityGateway):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Initialize real models if available
        if REAL_MODELS_AVAILABLE:
            try:
                self.real_security_model = RealSecurityModel()
                self.real_trust_model = RealTrustModel()
            except Exception as e:
                print(f"Warning: Could not initialize real models: {e}")
                self.real_security_model = None
                self.real_trust_model = None
        else:
            self.real_security_model = None
            self.real_trust_model = None
            
        self.logger = logging.getLogger(__name__)
        
        # Real-time metrics
        self.metrics = {
            "requests_processed": 0,
            "threats_detected": 0,
            "trust_adjustments": 0,
            "response_times": []
        }
    
    async def process_request(self, agent_id: str, request: RequestContext) -> ResponseContext:
        """Process request with real ML models"""
        start_time = time.time()
        
        try:
            # 1. Real threat detection
            threat_result = {"threat_level": "safe", "confidence": 0.0, "is_threat": False}
            if self.real_security_model:
                threat_result = self.real_security_model.detect_threat(
                    f"{request.operation} {request.resource}"
                )
            
            if threat_result["is_threat"]:
                self.metrics["threats_detected"] += 1
                return ResponseContext(
                    status="blocked",
                    message=f"Request blocked: {threat_result['threat_level']} threat detected",
                    security_assessment={
                        "threat_level": threat_result["threat_level"],
                        "confidence": threat_result["confidence"]
                    }
                )
            
            # 2. Real trust calculation
            trust_score = 0.5  # Default
            if self.real_trust_model:
                trust_score = self.real_trust_model.calculate_trust_score(
                    agent_id, [f"{request.operation} {request.resource}"]
                )
            
            # 3. Process through base gateway
            response = await super().process_request(agent_id, request)
            
            # 4. Update metrics
            response_time = time.time() - start_time
            self.metrics["requests_processed"] += 1
            self.metrics["response_times"].append(response_time)
            
            # Add real-time data to response
            response.trust_score = trust_score
            response.threat_assessment = threat_result
            response.response_time = response_time
            
            return response
            
        except Exception as e:
            self.logger.error(f"Request processing error: {e}")
            return ResponseContext(
                status="error",
                message=f"Processing failed: {str(e)}"
            )
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time performance metrics"""
        response_times = self.metrics["response_times"]
        
        return {
            "requests_processed": self.metrics["requests_processed"],
            "threats_detected": self.metrics["threats_detected"],
            "average_response_time": sum(response_times) / len(response_times) if response_times else 0,
            "threat_detection_rate": self.metrics["threats_detected"] / max(1, self.metrics["requests_processed"]),
            "throughput": self.metrics["requests_processed"] / max(1, sum(response_times)) if response_times else 0
        }
