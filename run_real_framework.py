#!/usr/bin/env python3
"""
MCP Security Framework - Real Framework Runner
==============================================

This script runs the MCP Security Framework in real mode with actual
implementations and real-world scenarios.

Usage:
    python run_real_framework.py [options]

Options:
    --config FILE         Configuration file path
    --mode MODE           Framework mode (development, production, test)
    --port PORT           API port (default: 8000)
    --workers WORKERS     Number of worker processes
    --monitor             Enable monitoring
    --benchmark           Run benchmark after startup
    --verbose             Enable verbose output
"""

import sys
import os
import asyncio
import argparse
import signal
import time
from pathlib import Path
from typing import Optional, Dict, Any

# Add the framework to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mcp_security_framework'))

from mcp_security_framework.core.gateway import MCPSecurityGateway
from mcp_security_framework.core.identity import IdentityManager, AgentType
from mcp_security_framework.core.trust import TrustCalculator, TrustEvent, TrustEventType
from mcp_security_framework.core.policy import PolicyEngine, PolicyContext
from mcp_security_framework.core.registry import ToolRegistry


class RealFrameworkRunner:
    """Real framework runner for MCP Security Framework"""
    
    def __init__(self, config_path: str = "config/security_config.yaml", 
                 mode: str = "development", port: int = 8000, 
                 workers: int = 4, monitor: bool = False, verbose: bool = False):
        self.config_path = config_path
        self.mode = mode
        self.port = port
        self.workers = workers
        self.monitor = monitor
        self.verbose = verbose
        
        self.gateway: Optional[MCPSecurityGateway] = None
        self.running = False
        self.start_time = time.time()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def log(self, message: str, level: str = "INFO"):
        """Log framework messages"""
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {message}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.log(f"Received signal {signum}, shutting down...")
        self.running = False
    
    async def initialize_framework(self) -> bool:
        """Initialize the MCP Security Framework"""
        self.log("🔧 Initializing MCP Security Framework...")
        
        try:
            # Initialize gateway
            self.gateway = MCPSecurityGateway(config_path=self.config_path)
            self.log("✅ Gateway initialized")
            
            # Initialize components
            self.log("🔧 Initializing framework components...")
            
            # Test identity manager
            identity_manager = self.gateway.identity_manager
            if identity_manager:
                self.log("✅ Identity Manager initialized")
            else:
                self.log("❌ Identity Manager initialization failed", "ERROR")
                return False
            
            # Test trust calculator
            trust_calculator = self.gateway.trust_calculator
            if trust_calculator:
                self.log("✅ Trust Calculator initialized")
            else:
                self.log("❌ Trust Calculator initialization failed", "ERROR")
                return False
            
            # Test policy engine
            policy_engine = self.gateway.policy_engine
            if policy_engine:
                self.log("✅ Policy Engine initialized")
            else:
                self.log("❌ Policy Engine initialization failed", "ERROR")
                return False
            
            # Test tool registry
            tool_registry = self.gateway.tool_registry
            if tool_registry:
                self.log("✅ Tool Registry initialized")
            else:
                self.log("❌ Tool Registry initialization failed", "ERROR")
                return False
            
            self.log("✅ Framework initialization completed")
            return True
            
        except Exception as e:
            self.log(f"❌ Framework initialization failed: {e}", "ERROR")
            return False
    
    async def setup_demo_agents(self) -> bool:
        """Setup demo agents for testing"""
        self.log("👥 Setting up demo agents...")
        
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            
            # Create demo agents
            demo_agents = [
                {
                    "id": "admin_demo",
                    "type": AgentType.ADMIN,
                    "capabilities": ["admin", "user_management", "system_config"]
                },
                {
                    "id": "user_demo",
                    "type": AgentType.USER,
                    "capabilities": ["read", "write", "execute"]
                },
                {
                    "id": "service_demo",
                    "type": AgentType.SERVICE,
                    "capabilities": ["api_access", "data_processing"]
                },
                {
                    "id": "guest_demo",
                    "type": AgentType.GUEST,
                    "capabilities": ["read_public"]
                }
            ]
            
            for agent_config in demo_agents:
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()
                
                # Serialize public key
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Register agent
                success, message = self.gateway.identity_manager.register_agent(
                    agent_id=agent_config["id"],
                    public_key=public_key_bytes,
                    agent_type=agent_config["type"],
                    capabilities=agent_config["capabilities"]
                )
                
                if success:
                    self.log(f"✅ Created demo agent: {agent_config['id']}")
                else:
                    self.log(f"❌ Failed to create demo agent {agent_config['id']}: {message}", "ERROR")
                    return False
            
            self.log("✅ Demo agents setup completed")
            return True
            
        except Exception as e:
            self.log(f"❌ Demo agents setup failed: {e}", "ERROR")
            return False
    
    async def build_trust_relationships(self) -> bool:
        """Build trust relationships between agents"""
        self.log("🤝 Building trust relationships...")
        
        try:
            # Add trust events for demo agents
            trust_events = [
                # Admin agent - high trust
                TrustEvent(
                    event_id="admin_trust_1",
                    agent_id="admin_demo",
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 100,
                    value=0.9,
                    context={"task": "system_maintenance"}
                ),
                TrustEvent(
                    event_id="admin_trust_2",
                    agent_id="admin_demo",
                    event_type=TrustEventType.SUCCESSFUL_OPERATION,
                    timestamp=time.time() - 80,
                    value=0.95,
                    context={"operation": "user_management"}
                ),
                # User agent - medium trust
                TrustEvent(
                    event_id="user_trust_1",
                    agent_id="user_demo",
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 60,
                    value=0.7,
                    context={"task": "data_processing"}
                ),
                TrustEvent(
                    event_id="user_trust_2",
                    agent_id="user_demo",
                    event_type=TrustEventType.COOPERATION_POSITIVE,
                    timestamp=time.time() - 40,
                    value=0.8,
                    context={"cooperation": "team_work"}
                ),
                # Service agent - high trust
                TrustEvent(
                    event_id="service_trust_1",
                    agent_id="service_demo",
                    event_type=TrustEventType.SUCCESSFUL_OPERATION,
                    timestamp=time.time() - 30,
                    value=0.9,
                    context={"operation": "api_service"}
                ),
                # Guest agent - low trust
                TrustEvent(
                    event_id="guest_trust_1",
                    agent_id="guest_demo",
                    event_type=TrustEventType.TASK_SUCCESS,
                    timestamp=time.time() - 20,
                    value=0.5,
                    context={"task": "public_access"}
                )
            ]
            
            # Add events to trust calculator
            for event in trust_events:
                success = self.gateway.trust_calculator.add_trust_event(event)
                if not success:
                    self.log(f"❌ Failed to add trust event: {event.event_id}", "ERROR")
                    return False
            
            # Wait for processing
            await asyncio.sleep(0.1)
            
            # Verify trust scores
            for agent_id in ["admin_demo", "user_demo", "service_demo", "guest_demo"]:
                trust_score = self.gateway.trust_calculator.get_trust_score(agent_id)
                if trust_score:
                    self.log(f"✅ Trust score for {agent_id}: {trust_score.overall_score:.3f}")
                else:
                    self.log(f"⚠️ No trust score for {agent_id}", "WARNING")
            
            self.log("✅ Trust relationships built successfully")
            return True
            
        except Exception as e:
            self.log(f"❌ Trust relationship building failed: {e}", "ERROR")
            return False
    
    async def run_demo_scenarios(self) -> bool:
        """Run demo scenarios"""
        self.log("🎭 Running demo scenarios...")
        
        try:
            # Scenario 1: Admin access
            admin_context = PolicyContext(
                agent_id="admin_demo",
                resource="admin_resources",
                action="read",
                agent_type=AgentType.ADMIN,
                trust_score=0.9
            )
            
            decision = self.gateway.policy_engine.evaluate_access(admin_context)
            self.log(f"✅ Admin access scenario: {decision.decision} - {decision.reason}")
            
            # Scenario 2: User access
            user_context = PolicyContext(
                agent_id="user_demo",
                resource="user_resources",
                action="write",
                agent_type=AgentType.USER,
                trust_score=0.7
            )
            
            decision = self.gateway.policy_engine.evaluate_access(user_context)
            self.log(f"✅ User access scenario: {decision.decision} - {decision.reason}")
            
            # Scenario 3: Guest access
            guest_context = PolicyContext(
                agent_id="guest_demo",
                resource="public_resources",
                action="read",
                agent_type=AgentType.GUEST,
                trust_score=0.5
            )
            
            decision = self.gateway.policy_engine.evaluate_access(guest_context)
            self.log(f"✅ Guest access scenario: {decision.decision} - {decision.reason}")
            
            # Scenario 4: Denied access
            denied_context = PolicyContext(
                agent_id="guest_demo",
                resource="admin_resources",
                action="write",
                agent_type=AgentType.GUEST,
                trust_score=0.5
            )
            
            decision = self.gateway.policy_engine.evaluate_access(denied_context)
            self.log(f"✅ Denied access scenario: {decision.decision} - {decision.reason}")
            
            self.log("✅ Demo scenarios completed successfully")
            return True
            
        except Exception as e:
            self.log(f"❌ Demo scenarios failed: {e}", "ERROR")
            return False
    
    async def start_monitoring(self):
        """Start monitoring if enabled"""
        if not self.monitor:
            return
        
        self.log("📊 Starting monitoring...")
        
        try:
            # Start monitoring in background
            import subprocess
            monitor_process = subprocess.Popen([
                sys.executable, "monitor.py", "--interval", "10"
            ])
            
            self.log("✅ Monitoring started")
            return monitor_process
            
        except Exception as e:
            self.log(f"❌ Failed to start monitoring: {e}", "ERROR")
            return None
    
    async def run_benchmark(self) -> bool:
        """Run benchmark if requested"""
        self.log("📊 Running benchmark...")
        
        try:
            import subprocess
            result = subprocess.run([
                sys.executable, "benchmark/optimized_real_benchmark.py"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("✅ Benchmark completed successfully")
                return True
            else:
                self.log(f"❌ Benchmark failed: {result.stderr}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"❌ Benchmark execution failed: {e}", "ERROR")
            return False
    
    async def run_framework(self) -> bool:
        """Run the MCP Security Framework"""
        self.log("🚀 Starting MCP Security Framework...")
        
        try:
            # Initialize framework
            if not await self.initialize_framework():
                return False
            
            # Setup demo agents
            if not await self.setup_demo_agents():
                return False
            
            # Build trust relationships
            if not await self.build_trust_relationships():
                return False
            
            # Run demo scenarios
            if not await self.run_demo_scenarios():
                return False
            
            # Start monitoring if enabled
            monitor_process = await self.start_monitoring()
            
            # Run benchmark if requested
            if hasattr(self, 'run_benchmark_flag') and self.run_benchmark_flag:
                await self.run_benchmark()
            
            # Keep framework running
            self.running = True
            self.log("🎉 Framework is running successfully!")
            self.log("Press Ctrl+C to stop")
            
            while self.running:
                await asyncio.sleep(1)
            
            # Cleanup
            if monitor_process:
                monitor_process.terminate()
                self.log("📊 Monitoring stopped")
            
            self.log("🛑 Framework stopped")
            return True
            
        except Exception as e:
            self.log(f"❌ Framework execution failed: {e}", "ERROR")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Real Framework Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_real_framework.py
    python run_real_framework.py --mode production --port 8080
    python run_real_framework.py --monitor --benchmark
    python run_real_framework.py --config custom_config.yaml --verbose
        """
    )
    
    parser.add_argument(
        "--config",
        default="config/security_config.yaml",
        help="Configuration file path"
    )
    
    parser.add_argument(
        "--mode",
        choices=["development", "production", "test"],
        default="development",
        help="Framework mode"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API port"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker processes"
    )
    
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Enable monitoring"
    )
    
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run benchmark after startup"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Create framework runner
    runner = RealFrameworkRunner(
        config_path=args.config,
        mode=args.mode,
        port=args.port,
        workers=args.workers,
        monitor=args.monitor,
        verbose=args.verbose
    )
    
    # Set benchmark flag
    runner.run_benchmark_flag = args.benchmark
    
    # Run framework
    success = asyncio.run(runner.run_framework())
    
    if success:
        print("\n🎉 Framework completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Framework execution failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()