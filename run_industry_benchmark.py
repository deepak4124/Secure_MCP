#!/usr/bin/env python3
"""
MCP Security Framework - Industry Benchmark Runner
=================================================

This script runs industry-standard benchmarks for the MCP Security Framework
and compares results with other frameworks.

Usage:
    python run_industry_benchmark.py [options]

Options:
    --framework FRAMEWORK    Specific framework to benchmark
    --all                   Benchmark all frameworks
    --metrics METRICS       Specific metrics to test
    --output FILE           Output file for results
    --verbose               Enable verbose output
"""

import sys
import os
import asyncio
import argparse
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


class IndustryBenchmarkRunner:
    """Industry benchmark runner for MCP Security Framework"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.project_root = Path(__file__).parent
        self.benchmark_results = {}
        self.start_time = time.time()
    
    def log(self, message: str, level: str = "INFO"):
        """Log benchmark messages"""
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {message}")
    
    async def run_mcp_benchmark(self) -> Dict[str, Any]:
        """Run MCP Security Framework benchmark"""
        self.log("🔧 Running MCP Security Framework benchmark...")
        
        try:
            # Import and run the benchmark
            sys.path.insert(0, str(self.project_root / "benchmark"))
            from optimized_real_benchmark import OptimizedRealBenchmark
            
            benchmark = OptimizedRealBenchmark()
            results = await benchmark.run_benchmark()
            
            self.log("✅ MCP Security Framework benchmark completed")
            return results
            
        except Exception as e:
            self.log(f"❌ MCP benchmark failed: {e}", "ERROR")
            return {"error": str(e)}
    
    async def run_industry_comparison(self) -> Dict[str, Any]:
        """Run industry framework comparison"""
        self.log("📊 Running industry framework comparison...")
        
        try:
            # Import and run the industry comparison
            sys.path.insert(0, str(self.project_root))
            from mcp_security_framework.benchmarking.real_industry_benchmarker import RealIndustryBenchmarker
            
            benchmarker = RealIndustryBenchmarker()
            results = await benchmarker.run_comprehensive_benchmark()
            
            self.log("✅ Industry comparison completed")
            return results
            
        except Exception as e:
            self.log(f"❌ Industry comparison failed: {e}", "ERROR")
            return {"error": str(e)}
    
    async def run_validation_metrics(self) -> Dict[str, Any]:
        """Run validation metrics"""
        self.log("📈 Running validation metrics...")
        
        try:
            # Import and run validation metrics
            sys.path.insert(0, str(self.project_root))
            from mcp_security_framework.benchmarking.industry_validation_metrics import IndustryValidationMetrics
            
            validator = IndustryValidationMetrics()
            results = await validator.run_validation()
            
            self.log("✅ Validation metrics completed")
            return results
            
        except Exception as e:
            self.log(f"❌ Validation metrics failed: {e}", "ERROR")
            return {"error": str(e)}
    
    async def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run all benchmarks"""
        self.log("🚀 Starting comprehensive industry benchmarks...")
        
        results = {}
        
        # Run MCP benchmark
        results["mcp_framework"] = await self.run_mcp_benchmark()
        
        # Run industry comparison
        results["industry_comparison"] = await self.run_industry_comparison()
        
        # Run validation metrics
        results["validation_metrics"] = await self.run_validation_metrics()
        
        # Calculate overall results
        duration = time.time() - self.start_time
        results["metadata"] = {
            "timestamp": time.time(),
            "duration": duration,
            "framework": "MCP Security Framework",
            "version": "1.0.0"
        }
        
        self.log(f"📊 All benchmarks completed in {duration:.2f} seconds")
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_file: Optional[str] = None):
        """Save benchmark results to file"""
        try:
            if output_file:
                results_file = Path(output_file)
            else:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                results_file = self.project_root / "logs" / f"industry_benchmark_results_{timestamp}.json"
            
            results_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log(f"✅ Benchmark results saved to: {results_file}")
            
        except Exception as e:
            self.log(f"❌ Failed to save benchmark results: {e}", "ERROR")
    
    def print_summary(self, results: Dict[str, Any]):
        """Print benchmark summary"""
        self.log("📋 Benchmark Summary:")
        self.log("=" * 50)
        
        # MCP Framework results
        if "mcp_framework" in results and "error" not in results["mcp_framework"]:
            mcp_results = results["mcp_framework"]
            self.log(f"🔧 MCP Security Framework:")
            self.log(f"   Overall Success Rate: {mcp_results.get('overall_success_rate', 'N/A')}%")
            self.log(f"   Average Throughput: {mcp_results.get('average_throughput', 'N/A')} ops/sec")
            self.log(f"   Memory Usage: {mcp_results.get('average_memory_usage', 'N/A')} MB")
        
        # Industry comparison results
        if "industry_comparison" in results and "error" not in results["industry_comparison"]:
            industry_results = results["industry_comparison"]
            self.log(f"📊 Industry Comparison:")
            self.log(f"   Frameworks Compared: {len(industry_results.get('frameworks', {}))}")
            self.log(f"   MCP Ranking: {industry_results.get('mcp_ranking', 'N/A')}")
        
        # Validation metrics
        if "validation_metrics" in results and "error" not in results["validation_metrics"]:
            validation_results = results["validation_metrics"]
            self.log(f"📈 Validation Metrics:")
            self.log(f"   Compliance Score: {validation_results.get('compliance_score', 'N/A')}%")
            self.log(f"   Security Score: {validation_results.get('security_score', 'N/A')}%")
        
        self.log("=" * 50)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Industry Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_industry_benchmark.py
    python run_industry_benchmark.py --all
    python run_industry_benchmark.py --framework mcp
    python run_industry_benchmark.py --output results.json --verbose
        """
    )
    
    parser.add_argument(
        "--framework",
        help="Specific framework to benchmark"
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Benchmark all frameworks"
    )
    
    parser.add_argument(
        "--metrics",
        help="Specific metrics to test"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for results"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Create benchmark runner
    runner = IndustryBenchmarkRunner(verbose=args.verbose)
    
    # Run benchmarks
    async def run_benchmarks():
        if args.framework:
            if args.framework.lower() == "mcp":
                results = {"mcp_framework": await runner.run_mcp_benchmark()}
            else:
                runner.log(f"❌ Unknown framework: {args.framework}", "ERROR")
                return
        else:
            # Run all benchmarks by default
            results = await runner.run_all_benchmarks()
        
        # Save results
        runner.save_results(results, args.output)
        
        # Print summary
        runner.print_summary(results)
        
        # Check for errors
        has_errors = any("error" in result for result in results.values() if isinstance(result, dict))
        
        if has_errors:
            runner.log("❌ Some benchmarks failed!", "ERROR")
            sys.exit(1)
        else:
            runner.log("🎉 All benchmarks completed successfully!")
            sys.exit(0)
    
    # Run async benchmarks
    asyncio.run(run_benchmarks())


if __name__ == "__main__":
    main()
