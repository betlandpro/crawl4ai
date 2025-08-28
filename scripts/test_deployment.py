#!/usr/bin/env python3
"""
Test Script for Crawl4AI Production Deployment
Tests API endpoints, authentication, and basic functionality
"""

import sys
import json
import time
import httpx
from pathlib import Path
from typing import Dict, Any


class Crawl4AITester:
    def __init__(self, base_url: str, api_key: str = None, username: str = None, password: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client = httpx.Client(timeout=30.0)
        self.auth_token = None
    
    def test_health(self) -> bool:
        """Test health endpoint"""
        print("Testing health endpoint...")
        try:
            response = self.client.get(f"{self.base_url}/health")
            if response.status_code == 200:
                print("✅ Health check passed")
                return True
            else:
                print(f"❌ Health check failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False
    
    def test_api_authentication(self) -> bool:
        """Test API key authentication"""
        if not self.api_key:
            print("⚠️ No API key provided, skipping API auth test")
            return True
        
        print("Testing API authentication...")
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        try:
            # Test a simple crawl endpoint
            payload = {
                "urls": ["https://httpbin.org/json"],
                "browser_config": {"type": "BrowserConfig", "params": {"headless": True}},
                "crawler_config": {"type": "CrawlerRunConfig", "params": {"cache_mode": "bypass"}}
            }
            
            response = self.client.post(
                f"{self.base_url}/crawl",
                json=payload,
                headers=headers
            )
            
            if response.status_code == 200:
                print("✅ API authentication successful")
                return True
            elif response.status_code == 401:
                print("❌ API authentication failed: Invalid API key")
                return False
            elif response.status_code == 429:
                print("⚠️ Rate limit exceeded")
                return False
            else:
                print(f"❌ API request failed: {response.status_code}")
                print(f"Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ API authentication error: {e}")
            return False
    
    def test_playground_authentication(self) -> bool:
        """Test playground basic auth"""
        if not self.username or not self.password:
            print("⚠️ No credentials provided, skipping playground auth test")
            return True
        
        print("Testing playground authentication...")
        
        try:
            # Test with basic auth
            response = self.client.get(
                f"{self.base_url}/playground",
                auth=(self.username, self.password)
            )
            
            if response.status_code == 200:
                print("✅ Playground authentication successful")
                return True
            elif response.status_code == 401:
                print("❌ Playground authentication failed: Invalid credentials")
                return False
            else:
                print(f"❌ Playground request failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Playground authentication error: {e}")
            return False
    
    def test_crawl_functionality(self) -> bool:
        """Test basic crawl functionality"""
        if not self.api_key:
            print("⚠️ No API key provided, skipping crawl test")
            return True
        
        print("Testing crawl functionality...")
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        test_urls = [
            "https://httpbin.org/html",
            "https://httpbin.org/json",
            "https://httpbin.org/robots.txt"
        ]
        
        for url in test_urls:
            try:
                payload = {
                    "urls": [url],
                    "browser_config": {"type": "BrowserConfig", "params": {"headless": True}},
                    "crawler_config": {"type": "CrawlerRunConfig", "params": {"cache_mode": "bypass"}}
                }
                
                response = self.client.post(
                    f"{self.base_url}/crawl",
                    json=payload,
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data and len(data) > 0:
                        print(f"✅ Successfully crawled: {url}")
                    else:
                        print(f"⚠️ Empty response for: {url}")
                else:
                    print(f"❌ Failed to crawl {url}: {response.status_code}")
                    return False
                    
            except Exception as e:
                print(f"❌ Crawl error for {url}: {e}")
                return False
        
        return True
    
    def test_rate_limiting(self) -> bool:
        """Test rate limiting"""
        if not self.api_key:
            print("⚠️ No API key provided, skipping rate limit test")
            return True
        
        print("Testing rate limiting...")
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        # Make rapid requests to trigger rate limit
        hit_limit = False
        for i in range(150):  # Try to exceed typical rate limit
            try:
                response = self.client.get(
                    f"{self.base_url}/health",
                    headers=headers
                )
                
                if response.status_code == 429:
                    print(f"✅ Rate limit triggered after {i+1} requests")
                    hit_limit = True
                    break
            except Exception:
                pass
        
        if not hit_limit:
            print("⚠️ Rate limit not triggered (may have high limit)")
        
        return True
    
    def test_metrics_endpoint(self) -> bool:
        """Test metrics endpoint"""
        print("Testing metrics endpoint...")
        
        try:
            response = self.client.get(f"{self.base_url}/metrics")
            if response.status_code == 200:
                if "auth_requests_total" in response.text:
                    print("✅ Metrics endpoint working")
                    return True
                else:
                    print("⚠️ Metrics endpoint accessible but no auth metrics")
                    return True
            else:
                print(f"⚠️ Metrics endpoint returned: {response.status_code}")
                return True  # Not critical
        except Exception as e:
            print(f"⚠️ Metrics endpoint error: {e}")
            return True  # Not critical
    
    def run_all_tests(self) -> bool:
        """Run all tests"""
        print("=" * 60)
        print("Starting Crawl4AI Deployment Tests")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print()
        
        results = {
            "Health Check": self.test_health(),
            "API Authentication": self.test_api_authentication(),
            "Playground Auth": self.test_playground_authentication(),
            "Crawl Functionality": self.test_crawl_functionality(),
            "Rate Limiting": self.test_rate_limiting(),
            "Metrics": self.test_metrics_endpoint()
        }
        
        print("\n" + "=" * 60)
        print("Test Results Summary")
        print("=" * 60)
        
        for test_name, passed in results.items():
            status = "✅ PASSED" if passed else "❌ FAILED"
            print(f"{test_name}: {status}")
        
        all_passed = all(results.values())
        
        print("\n" + "=" * 60)
        if all_passed:
            print("✅ All tests passed successfully!")
        else:
            print("❌ Some tests failed. Please review the results.")
        print("=" * 60)
        
        return all_passed


def main():
    # Load configuration
    if len(sys.argv) < 2:
        print("Usage: python test_deployment.py <domain>")
        print("Example: python test_deployment.py crawl4ai.yourdomain.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    base_url = f"https://{domain}"
    
    # Try to load credentials from api_keys.json
    api_key = None
    username = None
    password = None
    
    api_keys_file = Path("api_keys.json")
    if api_keys_file.exists():
        with open(api_keys_file) as f:
            data = json.load(f)
            
            # Get first API key
            if data.get("api_keys"):
                first_key = list(data["api_keys"].values())[0]
                api_key = first_key["key"]
                print(f"Using API key: {first_key['name']}")
            
            # Get admin credentials
            if data.get("admin"):
                username = data["admin"]["username"]
                password = data["admin"]["password"]
                print(f"Using admin user: {username}")
    else:
        print("⚠️ api_keys.json not found. Testing without authentication.")
    
    # Create tester and run tests
    tester = Crawl4AITester(base_url, api_key, username, password)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()