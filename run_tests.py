#!/usr/bin/env python3
"""
MCP Security Framework - Test Runner
====================================

This script runs tests for the MCP Security Framework.
It provides a simple interface to run different types of tests.

Usage:
    python run_tests.py [options]

Options:
    --unit           Run unit tests only
    --integration    Run integration tests only
    --all            Run all tests (default)
    --verbose        Enable verbose output
    --coverage       Generate coverage report
    --quick          Run quick tests only
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path
from typing import List, Dict, Any


class TestRunner:
    """Test runner for MCP Security Framework"""
    
    def __init__(self, verbose: bool = False, coverage: bool = False):
        self.verbose = verbose
        self.coverage = coverage
        self.project_root = Path(__file__).parent
        self.test_results = {}
        self.start_time = time.time()
    
    def log(self, message: str, level: str = "INFO"):
        """Log test messages"""
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{timestamp}] [{level}]"
        print(f"{prefix} {message}")
    
    def run_pytest_tests(self, test_path: str, test_name: str) -> bool:
        """Run pytest tests"""
        self.log(f"🧪 Running {test_name}...")
        
        try:
            cmd = [sys.executable, "-m", "pytest", test_path, "-v"]
            
            if self.coverage:
                cmd.extend(["--cov=mcp_security_framework", "--cov-report=term"])
            
            if not self.verbose:
                cmd.append("-q")
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log(f"✅ {test_name} passed")
                self.test_results[test_name] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ {test_name} failed: {result.stderr}", "ERROR")
                self.test_results[test_name] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running {test_name}: {e}", "ERROR")
            return False
    
    def run_script_tests(self, script_path: str, test_name: str) -> bool:
        """Run script-based tests"""
        self.log(f"🧪 Running {test_name}...")
        
        try:
            cmd = [sys.executable, script_path]
            
            if self.verbose:
                cmd.append("--verbose")
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            if result.returncode == 0:
                self.log(f"✅ {test_name} passed")
                self.test_results[test_name] = {
                    "status": "passed",
                    "output": result.stdout
                }
                return True
            else:
                self.log(f"❌ {test_name} failed: {result.stderr}", "ERROR")
                self.test_results[test_name] = {
                    "status": "failed",
                    "output": result.stdout,
                    "error": result.stderr
                }
                return False
                
        except Exception as e:
            self.log(f"❌ Error running {test_name}: {e}", "ERROR")
            return False
    
    def run_unit_tests(self) -> bool:
        """Run unit tests"""
        return self.run_pytest_tests("tests/unit/", "Unit Tests")
    
    def run_integration_tests(self) -> bool:
        """Run integration tests"""
        # Run pytest integration tests
        pytest_result = self.run_pytest_tests("tests/integration/", "Integration Tests (pytest)")
        
        # Run script-based integration tests
        script_result = self.run_script_tests("test_integration_final.py", "Integration Tests (script)")
        
        return pytest_result and script_result
    
    def run_import_tests(self) -> bool:
        """Run import tests"""
        return self.run_script_tests("test_imports.py", "Import Tests")
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all tests"""
        self.log("🚀 Starting test suite...")
        
        test_results = {}
        
        # Run different test categories
        test_results["import_tests"] = self.run_import_tests()
        test_results["unit_tests"] = self.run_unit_tests()
        test_results["integration_tests"] = self.run_integration_tests()
        
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
            
            results_file = self.project_root / "logs" / "test_results.json"
            results_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(results_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            self.log(f"✅ Test results saved to: {results_file}")
            
        except Exception as e:
            self.log(f"❌ Failed to save test results: {e}", "ERROR")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_tests.py
    python run_tests.py --unit
    python run_tests.py --integration
    python run_tests.py --all --verbose --coverage
    python run_tests.py --quick
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
        "--quick",
        action="store_true",
        help="Run quick tests only"
    )
    
    args = parser.parse_args()
    
    # Create test runner
    runner = TestRunner(
        verbose=args.verbose,
        coverage=args.coverage
    )
    
    # Determine which tests to run
    if args.unit:
        results = {"unit_tests": runner.run_unit_tests()}
    elif args.integration:
        results = {"integration_tests": runner.run_integration_tests()}
    else:
        # Run all tests by default
        results = runner.run_all_tests()
    
    # Save results
    runner.save_results(results)
    
    # Exit with appropriate code
    success_rate = (sum(results.values()) / len(results)) * 100
    if success_rate >= 80:
        print(f"\n🎉 Tests completed successfully! ({success_rate:.1f}% pass rate)")
        sys.exit(0)
    else:
        print(f"\n❌ Tests failed! ({success_rate:.1f}% pass rate)")
        sys.exit(1)


if __name__ == "__main__":
    main()
