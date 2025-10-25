"""
Benchmark Runner for MCP Security Framework

This module provides a unified interface for running comprehensive benchmarks,
integrating all benchmarking components and providing automated execution
capabilities.
"""

import time
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import argparse
import sys

from pydantic import BaseModel, Field

from .metrics_collector import MetricsCollector, MetricCategory, MetricType
from .security_benchmarker import SecurityBenchmarker, AttackType, ThreatLevel
from .performance_benchmarker import PerformanceBenchmarker, LoadTestType, OperationType
from .compliance_benchmarker import ComplianceBenchmarker, ComplianceStandard, ComplianceLevel
from .benchmark_reporter import BenchmarkReporter, ReportType, ReportFormat


class BenchmarkScope(Enum):
    """Benchmark scope enumeration"""
    SECURITY_ONLY = "security_only"
    PERFORMANCE_ONLY = "performance_only"
    COMPLIANCE_ONLY = "compliance_only"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"


class BenchmarkConfig(BaseModel):
    """Benchmark configuration"""
    scope: BenchmarkScope = BenchmarkScope.COMPREHENSIVE
    security_tests: Optional[List[str]] = None
    performance_tests: Optional[List[str]] = None
    compliance_standards: Optional[List[ComplianceStandard]] = None
    iterations: int = 10
    warmup_duration: int = 60
    output_directory: str = "./benchmark_results"
    report_formats: List[ReportFormat] = [ReportFormat.JSON, ReportFormat.HTML]
    enable_metrics_collection: bool = True
    enable_real_time_monitoring: bool = True
    parallel_execution: bool = True
    max_concurrent_tests: int = 5


@dataclass
class BenchmarkExecution:
    """Benchmark execution tracking"""
    execution_id: str
    start_time: float
    end_time: Optional[float] = None
    status: str = "running"  # "running", "completed", "failed", "cancelled"
    progress: float = 0.0
    current_test: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class BenchmarkRunner:
    """
    Unified benchmark runner for MCP Security Framework
    
    Provides automated execution of comprehensive benchmarks, integrating
    security, performance, and compliance testing with real-time monitoring
    and reporting capabilities.
    """
    
    def __init__(self, config: Optional[BenchmarkConfig] = None):
        """
        Initialize benchmark runner
        
        Args:
            config: Benchmark configuration
        """
        self.config = config or BenchmarkConfig()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.metrics_collector = MetricsCollector()
        self.security_benchmarker = SecurityBenchmarker(self.metrics_collector)
        self.performance_benchmarker = PerformanceBenchmarker(self.metrics_collector)
        self.compliance_benchmarker = ComplianceBenchmarker(self.metrics_collector)
        self.benchmark_reporter = BenchmarkReporter(
            self.metrics_collector,
            self.security_benchmarker,
            self.performance_benchmarker,
            self.compliance_benchmarker
        )
        
        # Execution tracking
        self.current_execution: Optional[BenchmarkExecution] = None
        self.execution_history: List[BenchmarkExecution] = []
        
        # Create output directory
        self.output_dir = Path(self.config.output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("benchmark_runner")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    async def run_benchmark(
        self,
        framework_instance: Any,
        config: Optional[BenchmarkConfig] = None
    ) -> Dict[str, Any]:
        """
        Run comprehensive benchmark
        
        Args:
            framework_instance: Instance of the security framework to benchmark
            config: Optional benchmark configuration override
            
        Returns:
            Dictionary containing benchmark results
        """
        # Use provided config or default
        benchmark_config = config or self.config
        
        # Create execution tracking
        execution_id = f"benchmark_{int(time.time())}"
        self.current_execution = BenchmarkExecution(
            execution_id=execution_id,
            start_time=time.time()
        )
        
        self.logger.info(f"Starting benchmark execution: {execution_id}")
        
        try:
            # Run benchmark based on scope
            if benchmark_config.scope == BenchmarkScope.SECURITY_ONLY:
                results = await self._run_security_benchmark(framework_instance, benchmark_config)
            elif benchmark_config.scope == BenchmarkScope.PERFORMANCE_ONLY:
                results = await self._run_performance_benchmark(framework_instance, benchmark_config)
            elif benchmark_config.scope == BenchmarkScope.COMPLIANCE_ONLY:
                results = await self._run_compliance_benchmark(framework_instance, benchmark_config)
            elif benchmark_config.scope == BenchmarkScope.COMPREHENSIVE:
                results = await self._run_comprehensive_benchmark(framework_instance, benchmark_config)
            else:
                results = await self._run_custom_benchmark(framework_instance, benchmark_config)
            
            # Generate reports
            reports = await self._generate_reports(benchmark_config)
            results["reports"] = reports
            
            # Update execution status
            self.current_execution.status = "completed"
            self.current_execution.end_time = time.time()
            self.current_execution.results = results
            self.current_execution.progress = 100.0
            
            self.logger.info(f"Benchmark execution completed: {execution_id}")
            
        except Exception as e:
            self.logger.error(f"Benchmark execution failed: {e}")
            self.current_execution.status = "failed"
            self.current_execution.end_time = time.time()
            self.current_execution.errors.append(str(e))
            raise
        
        finally:
            # Add to execution history
            self.execution_history.append(self.current_execution)
            self.current_execution = None
        
        return results
    
    async def _run_security_benchmark(
        self,
        framework_instance: Any,
        config: BenchmarkConfig
    ) -> Dict[str, Any]:
        """Run security benchmark only"""
        self.logger.info("Running security benchmark...")
        
        self.current_execution.current_test = "security_benchmark"
        self.current_execution.progress = 10.0
        
        security_results = await self.security_benchmarker.run_security_benchmark(
            framework_instance=framework_instance,
            test_scenarios=config.security_tests,
            iterations=config.iterations
        )
        
        self.current_execution.progress = 50.0
        
        return {
            "security_results": security_results,
            "benchmark_type": "security_only",
            "execution_time": time.time() - self.current_execution.start_time
        }
    
    async def _run_performance_benchmark(
        self,
        framework_instance: Any,
        config: BenchmarkConfig
    ) -> Dict[str, Any]:
        """Run performance benchmark only"""
        self.logger.info("Running performance benchmark...")
        
        self.current_execution.current_test = "performance_benchmark"
        self.current_execution.progress = 10.0
        
        performance_results = await self.performance_benchmarker.run_performance_benchmark(
            framework_instance=framework_instance,
            test_ids=config.performance_tests,
            warmup_duration=config.warmup_duration
        )
        
        self.current_execution.progress = 50.0
        
        return {
            "performance_results": performance_results,
            "benchmark_type": "performance_only",
            "execution_time": time.time() - self.current_execution.start_time
        }
    
    async def _run_compliance_benchmark(
        self,
        framework_instance: Any,
        config: BenchmarkConfig
    ) -> Dict[str, Any]:
        """Run compliance benchmark only"""
        self.logger.info("Running compliance benchmark...")
        
        self.current_execution.current_test = "compliance_benchmark"
        self.current_execution.progress = 10.0
        
        compliance_results = await self.compliance_benchmarker.run_compliance_benchmark(
            framework_instance=framework_instance,
            standards=config.compliance_standards
        )
        
        self.current_execution.progress = 50.0
        
        return {
            "compliance_results": compliance_results,
            "benchmark_type": "compliance_only",
            "execution_time": time.time() - self.current_execution.start_time
        }
    
    async def _run_comprehensive_benchmark(
        self,
        framework_instance: Any,
        config: BenchmarkConfig
    ) -> Dict[str, Any]:
        """Run comprehensive benchmark (all types)"""
        self.logger.info("Running comprehensive benchmark...")
        
        results = {
            "benchmark_type": "comprehensive",
            "start_time": time.time()
        }
        
        # Run security benchmark
        self.current_execution.current_test = "security_benchmark"
        self.current_execution.progress = 10.0
        
        security_results = await self.security_benchmarker.run_security_benchmark(
            framework_instance=framework_instance,
            test_scenarios=config.security_tests,
            iterations=config.iterations
        )
        results["security_results"] = security_results
        
        # Run performance benchmark
        self.current_execution.current_test = "performance_benchmark"
        self.current_execution.progress = 40.0
        
        performance_results = await self.performance_benchmarker.run_performance_benchmark(
            framework_instance=framework_instance,
            test_ids=config.performance_tests,
            warmup_duration=config.warmup_duration
        )
        results["performance_results"] = performance_results
        
        # Run compliance benchmark
        self.current_execution.current_test = "compliance_benchmark"
        self.current_execution.progress = 70.0
        
        compliance_results = await self.compliance_benchmarker.run_compliance_benchmark(
            framework_instance=framework_instance,
            standards=config.compliance_standards
        )
        results["compliance_results"] = compliance_results
        
        results["end_time"] = time.time()
        results["execution_time"] = results["end_time"] - results["start_time"]
        
        return results
    
    async def _run_custom_benchmark(
        self,
        framework_instance: Any,
        config: BenchmarkConfig
    ) -> Dict[str, Any]:
        """Run custom benchmark based on configuration"""
        self.logger.info("Running custom benchmark...")
        
        results = {
            "benchmark_type": "custom",
            "start_time": time.time()
        }
        
        # Run selected benchmarks based on configuration
        if config.security_tests:
            self.current_execution.current_test = "security_benchmark"
            security_results = await self.security_benchmarker.run_security_benchmark(
                framework_instance=framework_instance,
                test_scenarios=config.security_tests,
                iterations=config.iterations
            )
            results["security_results"] = security_results
        
        if config.performance_tests:
            self.current_execution.current_test = "performance_benchmark"
            performance_results = await self.performance_benchmarker.run_performance_benchmark(
                framework_instance=framework_instance,
                test_ids=config.performance_tests,
                warmup_duration=config.warmup_duration
            )
            results["performance_results"] = performance_results
        
        if config.compliance_standards:
            self.current_execution.current_test = "compliance_benchmark"
            compliance_results = await self.compliance_benchmarker.run_compliance_benchmark(
                framework_instance=framework_instance,
                standards=config.compliance_standards
            )
            results["compliance_results"] = compliance_results
        
        results["end_time"] = time.time()
        results["execution_time"] = results["end_time"] - results["start_time"]
        
        return results
    
    async def _generate_reports(self, config: BenchmarkConfig) -> Dict[str, Any]:
        """Generate benchmark reports"""
        self.logger.info("Generating benchmark reports...")
        
        self.current_execution.current_test = "report_generation"
        self.current_execution.progress = 80.0
        
        reports = {}
        
        for report_format in config.report_formats:
            try:
                report = self.benchmark_reporter.generate_comprehensive_report(
                    report_type=ReportType.COMPREHENSIVE,
                    format=report_format
                )
                
                # Save report to file
                report_filename = f"benchmark_report_{int(time.time())}.{report_format.value}"
                report_path = self.output_dir / report_filename
                
                if report_format == ReportFormat.JSON:
                    with open(report_path, 'w') as f:
                        json.dump(report, f, indent=2)
                else:
                    # For other formats, save as text
                    with open(report_path, 'w') as f:
                        f.write(str(report))
                
                reports[report_format.value] = {
                    "content": report,
                    "file_path": str(report_path)
                }
                
                self.logger.info(f"Report generated: {report_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {report_format.value} report: {e}")
                reports[report_format.value] = {"error": str(e)}
        
        return reports
    
    def get_execution_status(self) -> Optional[Dict[str, Any]]:
        """
        Get current execution status
        
        Returns:
            Dictionary containing execution status or None if no active execution
        """
        if not self.current_execution:
            return None
        
        return {
            "execution_id": self.current_execution.execution_id,
            "status": self.current_execution.status,
            "progress": self.current_execution.progress,
            "current_test": self.current_execution.current_test,
            "start_time": self.current_execution.start_time,
            "elapsed_time": time.time() - self.current_execution.start_time,
            "errors": self.current_execution.errors
        }
    
    def get_execution_history(self) -> List[Dict[str, Any]]:
        """
        Get execution history
        
        Returns:
            List of execution history entries
        """
        return [
            {
                "execution_id": execution.execution_id,
                "start_time": execution.start_time,
                "end_time": execution.end_time,
                "status": execution.status,
                "duration": execution.end_time - execution.start_time if execution.end_time else None,
                "errors": execution.errors
            }
            for execution in self.execution_history
        ]
    
    def cancel_current_execution(self) -> bool:
        """
        Cancel current execution
        
        Returns:
            True if execution was cancelled, False if no active execution
        """
        if not self.current_execution:
            return False
        
        self.current_execution.status = "cancelled"
        self.current_execution.end_time = time.time()
        self.logger.info(f"Benchmark execution cancelled: {self.current_execution.execution_id}")
        
        return True
    
    def export_metrics(self, file_path: str) -> None:
        """
        Export collected metrics
        
        Args:
            file_path: Path to export file
        """
        self.metrics_collector.export_metrics(file_path)
        self.logger.info(f"Metrics exported to: {file_path}")
    
    def import_metrics(self, file_path: str) -> None:
        """
        Import metrics from file
        
        Args:
            file_path: Path to import file
        """
        self.metrics_collector.import_metrics(file_path)
        self.logger.info(f"Metrics imported from: {file_path}")
    
    def get_benchmark_summary(self) -> Dict[str, Any]:
        """
        Get benchmark summary
        
        Returns:
            Dictionary containing benchmark summary
        """
        return {
            "total_executions": len(self.execution_history),
            "successful_executions": len([
                e for e in self.execution_history if e.status == "completed"
            ]),
            "failed_executions": len([
                e for e in self.execution_history if e.status == "failed"
            ]),
            "cancelled_executions": len([
                e for e in self.execution_history if e.status == "cancelled"
            ]),
            "current_execution": self.get_execution_status(),
            "metrics_summary": self.metrics_collector.get_metric_summary(),
            "available_tests": {
                "security_tests": list(self.security_benchmarker.attack_scenarios.keys()),
                "performance_tests": list(self.performance_benchmarker.performance_tests.keys()),
                "compliance_standards": [s.value for s in ComplianceStandard]
            }
        }


# CLI Interface
def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework Benchmark Runner"
    )
    
    parser.add_argument(
        "--scope",
        choices=[s.value for s in BenchmarkScope],
        default=BenchmarkScope.COMPREHENSIVE.value,
        help="Benchmark scope"
    )
    
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of iterations for security tests"
    )
    
    parser.add_argument(
        "--warmup-duration",
        type=int,
        default=60,
        help="Warmup duration in seconds"
    )
    
    parser.add_argument(
        "--output-dir",
        default="./benchmark_results",
        help="Output directory for results"
    )
    
    parser.add_argument(
        "--report-formats",
        nargs="+",
        choices=[f.value for f in ReportFormat],
        default=[ReportFormat.JSON.value],
        help="Report formats to generate"
    )
    
    parser.add_argument(
        "--security-tests",
        nargs="+",
        help="Specific security tests to run"
    )
    
    parser.add_argument(
        "--performance-tests",
        nargs="+",
        help="Specific performance tests to run"
    )
    
    parser.add_argument(
        "--compliance-standards",
        nargs="+",
        choices=[s.value for s in ComplianceStandard],
        help="Specific compliance standards to assess"
    )
    
    parser.add_argument(
        "--export-metrics",
        help="Export metrics to file"
    )
    
    parser.add_argument(
        "--import-metrics",
        help="Import metrics from file"
    )
    
    return parser


async def main():
    """Main CLI entry point"""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Create benchmark configuration
    config = BenchmarkConfig(
        scope=BenchmarkScope(args.scope),
        iterations=args.iterations,
        warmup_duration=args.warmup_duration,
        output_directory=args.output_dir,
        report_formats=[ReportFormat(f) for f in args.report_formats],
        security_tests=args.security_tests,
        performance_tests=args.performance_tests,
        compliance_standards=[
            ComplianceStandard(s) for s in (args.compliance_standards or [])
        ]
    )
    
    # Create benchmark runner
    runner = BenchmarkRunner(config)
    
    # Handle import/export
    if args.import_metrics:
        runner.import_metrics(args.import_metrics)
    
    if args.export_metrics:
        runner.export_metrics(args.export_metrics)
        return
    
    # Create a mock framework instance for demonstration
    # In real usage, this would be an actual framework instance
    class MockFramework:
        def __init__(self):
            self.name = "MCP Security Framework"
            self.version = "1.0.0"
    
    framework_instance = MockFramework()
    
    try:
        # Run benchmark
        results = await runner.run_benchmark(framework_instance, config)
        
        print("Benchmark completed successfully!")
        print(f"Results saved to: {config.output_directory}")
        
        # Print summary
        summary = runner.get_benchmark_summary()
        print(f"Total executions: {summary['total_executions']}")
        print(f"Successful executions: {summary['successful_executions']}")
        
    except Exception as e:
        print(f"Benchmark failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
