#!/usr/bin/env python3
"""
MCP Security Framework - Comprehensive Test Runner
=================================================

This script runs comprehensive tests for the MCP Security Framework.
It executes unit tests, integration tests, and performance tests.

Usage:
    python run_comprehensive_tests.py [options]

Options:
    --unit           Run unit tests only
    --integration    Run integration tests only
    --performance    Run performance tests only
    --all            Run all tests (default)
    --verbose        Enable verbose output
    --coverage       Generate coverage report
    --parallel       Run tests in parallel
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path
from typing import List, Dict, Any


class ComprehensiveTestRunner:
    """Comprehensive test runner for MCP Security Framework"""
    
    def __init__(self, verbose: bool = False, coverage: bool = False, parallel: bool = False):
        self.verbose = verbose
        self.coverage = coverage
        self.parallel = parallel
        self.project_root = Path(__file__).parent
        self.test_results = {}
        self.start_time = time.time()
    
    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {message}")
    
    def run_unit_tests(self) -> bool:
        """Run unit tests"""
        self.log("🧪 Running unit tests...")
        
        try:
            cmd = [sys.executable, "-m", "pytest", "tests/unit/", "-v"]
            
            if self.coverage:
                cmd.extend(["--cov=mcp_security_framework", "--cov-report=html", "--cov-report=term"])
            
            if self.parallel:
                cmd.extend(["-n", "auto"])
            
            if not self.verbose:
                cmd.append("-q")
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log("✅ Unit tests passed")
                self.test_results["unit_tests"] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ Unit tests failed: {result.stderr}", "ERROR")
                self.test_results["unit_tests"] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running unit tests: {e}", "ERROR")
            return False
    
    def run_integration_tests(self) -> bool:
        """Run integration tests"""
        self.log("🧪 Running integration tests...")
        
        try:
            # Run the final integration test
            cmd = [sys.executable, "test_integration_final.py"]
            
            if self.verbose:
                cmd.append("--verbose")
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log("✅ Integration tests passed")
                self.test_results["integration_tests"] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ Integration tests failed: {result.stderr}", "ERROR")
                self.test_results["integration_tests"] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running integration tests: {e}", "ERROR")
            return False
    
    def run_performance_tests(self) -> bool:
        """Run performance tests"""
        self.log("🧪 Running performance tests...")
        
        try:
            # Run the benchmark
            cmd = [sys.executable, "benchmark/optimized_real_benchmark.py"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log("✅ Performance tests passed")
                self.test_results["performance_tests"] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ Performance tests failed: {result.stderr}", "ERROR")
                self.test_results["performance_tests"] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running performance tests: {e}", "ERROR")
            return False
    
    def run_import_tests(self) -> bool:
        """Run import tests"""
        self.log("🧪 Running import tests...")
        
        try:
            cmd = [sys.executable, "test_imports.py"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log("✅ Import tests passed")
                self.test_results["import_tests"] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ Import tests failed: {result.stderr}", "ERROR")
                self.test_results["import_tests"] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running import tests: {e}", "ERROR")
            return False
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all tests"""
        self.log("🚀 Starting comprehensive test suite...")
        
        test_results = {}
        
        # Run different test categories
        test_results["import_tests"] = self.run_import_tests()
        test_results["unit_tests"] = self.run_unit_tests()
        test_results["integration_tests"] = self.run_integration_tests()
        test_results["performance_tests"] = self.run_performance_tests()
        
        # Calculate overall results
        total_tests = len(test_results)
        passed_tests = sum(1 for result in test_results.values() if result)
        success_rate = (passed_tests / total_tests) * 100
        
        duration = time.time() - self.start_time
        
        self.log(f"📊 Test Results: {passed_tests}/{total_tests} test suites passed ({success_rate:.1f}%)")
        self.log(f"⏱️ Total duration: {duration:.2f} seconds")
        
        # Print detailed results
        for test_name, result in test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            self.log(f"  {test_name}: {status}")
        
        return test_results
    
    def save_results(self, results: Dict[str, bool]):
        """Save test results to file"""
        try:
            import json
            
            results_data = {
                "timestamp": time.time(),
                "duration": time.time() - self.start_time,
                "results": results,
                "success_rate": (sum(results.values()) / len(results)) * 100,
                "test_details": self.test_results
            }
            
            results_file = self.project_root / "logs" / "comprehensive_test_results.json"
            results_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(results_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            self.log(f"✅ Test results saved to: {results_file}")
            
        except Exception as e:
            self.log(f"❌ Failed to save test results: {e}", "ERROR")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Comprehensive Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_comprehensive_tests.py
    python run_comprehensive_tests.py --unit
    python run_comprehensive_tests.py --integration
    python run_comprehensive_tests.py --performance
    python run_comprehensive_tests.py --all --verbose --coverage
        """
    )
    
    parser.add_argument(
        "--unit",
        action="store_true",
        help="Run unit tests only"
    )
    
    parser.add_argument(
        "--integration",
        action="store_true",
        help="Run integration tests only"
    )
    
    parser.add_argument(
        "--performance",
        action="store_true",
        help="Run performance tests only"
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all tests (default)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Generate coverage report"
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run tests in parallel"
    )
    
    args = parser.parse_args()
    
    # Create test runner
    runner = ComprehensiveTestRunner(
        verbose=args.verbose,
        coverage=args.coverage,
        parallel=args.parallel
    )
    
    # Determine which tests to run
    if args.unit:
        results = {"unit_tests": runner.run_unit_tests()}
    elif args.integration:
        results = {"integration_tests": runner.run_integration_tests()}
    elif args.performance:
        results = {"performance_tests": runner.run_performance_tests()}
    else:
        # Run all tests by default
        results = runner.run_all_tests()
    
    # Save results
    runner.save_results(results)
    
    # Exit with appropriate code
    success_rate = (sum(results.values()) / len(results)) * 100
    if success_rate >= 80:
        print(f"\n🎉 Comprehensive tests completed successfully! ({success_rate:.1f}% pass rate)")
        sys.exit(0)
    else:
        print(f"\n❌ Comprehensive tests failed! ({success_rate:.1f}% pass rate)")
        sys.exit(1)


if __name__ == "__main__":
    main()
