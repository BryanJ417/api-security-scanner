from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
from enum import Enum
import asyncio
import httpx
import uuid
from datetime import datetime
import random
import re
from urllib.parse import urljoin, urlparse

app = FastAPI(title="API Security Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class APIType(str, Enum):
    rest = "rest"
    graphql = "graphql"
    soap = "soap"

class AuthType(str, Enum):
    none = "none"
    bearer = "bearer"
    basic = "basic"
    apikey = "apikey"
    oauth2 = "oauth2"

class ScanRequest(BaseModel):
    target_url: HttpUrl
    api_type: APIType
    auth_type: AuthType
    auth_token: Optional[str] = None

class Vulnerability(BaseModel):
    id: str
    title: str
    severity: str
    description: str
    endpoint: str
    evidence: str
    recommendation: str

class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    target: str
    api_type: str
    duration: str
    summary: Dict[str, int]
    vulnerabilities: List[Vulnerability]
    endpoints_tested: int
    requests_sent: int
    payloads_generated: int

scans_db = {}

# Real Fuzzing Payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' OR 'a'='a",
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    "$(whoami)",
    "; ping -c 10 127.0.0.1",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
]

class RealSecurityTester:
    def __init__(self, target_url: str, api_type: str, auth_token: Optional[str]):
        self.target_url = str(target_url).rstrip('/')
        self.api_type = api_type
        self.auth_token = auth_token
        self.vulnerabilities = []
        self.endpoints_tested = 0
        self.requests_sent = 0
        self.payloads_generated = 0
        self.client = httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False  # For testing purposes
        )
    
    def get_headers(self):
        """Get headers with authentication if provided"""
        headers = {
            "User-Agent": "API-Security-Scanner/1.0",
            "Accept": "application/json"
        }
        
        if self.auth_token:
            if self.auth_token.startswith("Bearer "):
                headers["Authorization"] = self.auth_token
            else:
                headers["Authorization"] = f"Bearer {self.auth_token}"
        
        return headers
    
    async def discover_endpoints(self):
        """Try to discover common API endpoints"""
        common_endpoints = [
            "/api/users",
            "/api/user",
            "/api/admin",
            "/api/auth",
            "/api/login",
            "/api/profile",
            "/api/data",
            "/api/search",
            "/users",
            "/user",
            "/admin",
            "/v1/users",
            "/v1/user"
        ]
        
        discovered = []
        for endpoint in common_endpoints:
            try:
                full_url = urljoin(self.target_url, endpoint)
                response = await self.client.get(full_url, headers=self.get_headers())
                self.requests_sent += 1
                
                if response.status_code in [200, 201, 401, 403]:
                    discovered.append(endpoint)
                    self.endpoints_tested += 1
            except:
                pass
        
        return discovered if discovered else ["/"]
    
    async def test_bola(self):
        """Test for Broken Object Level Authorization (REAL)"""
        try:
            # Test common BOLA patterns
            bola_patterns = [
                "/api/users/1",
                "/api/users/2",
                "/api/user/1",
                "/api/profile/1",
                "/users/1"
            ]
            
            for pattern in bola_patterns:
                full_url = urljoin(self.target_url, pattern)
                
                # Test 1: Access without authentication
                try:
                    response_no_auth = await self.client.get(full_url)
                    self.requests_sent += 1
                    
                    if response_no_auth.status_code == 200:
                        vuln = Vulnerability(
                            id="API1:2023",
                            title="Broken Object Level Authorization",
                            severity="critical",
                            description="Endpoint returns user data without authentication",
                            endpoint=pattern,
                            evidence=f"HTTP {response_no_auth.status_code} - Accessible without auth. Response length: {len(response_no_auth.text)} bytes",
                            recommendation="Implement authentication and authorization checks before returning user objects"
                        )
                        self.vulnerabilities.append(vuln)
                        return
                except:
                    pass
                
                # Test 2: ID Enumeration
                if self.auth_token:
                    accessible_ids = []
                    for user_id in range(1, 11):  # Test first 10 IDs
                        try:
                            test_url = urljoin(self.target_url, f"/api/users/{user_id}")
                            response = await self.client.get(test_url, headers=self.get_headers())
                            self.requests_sent += 1
                            
                            if response.status_code == 200:
                                accessible_ids.append(user_id)
                        except:
                            pass
                    
                    if len(accessible_ids) > 5:  # If we can access many user IDs
                        vuln = Vulnerability(
                            id="API1:2023",
                            title="Broken Object Level Authorization",
                            severity="critical",
                            description="API allows enumeration and access to multiple user objects",
                            endpoint="/api/users/{id}",
                            evidence=f"Successfully accessed {len(accessible_ids)} different user IDs: {accessible_ids}",
                            recommendation="Verify that authenticated users can only access their own objects"
                        )
                        self.vulnerabilities.append(vuln)
                        return
        except Exception as e:
            print(f"BOLA test error: {e}")
    
    async def test_authentication(self):
        """Test for Broken Authentication (REAL)"""
        try:
            protected_endpoints = [
                "/api/admin",
                "/api/profile",
                "/api/user/me",
                "/admin",
                "/api/protected"
            ]
            
            for endpoint in protected_endpoints:
                full_url = urljoin(self.target_url, endpoint)
                
                try:
                    # Test accessing protected endpoint without auth
                    response = await self.client.get(full_url)
                    self.requests_sent += 1
                    
                    if response.status_code == 200:
                        vuln = Vulnerability(
                            id="API2:2023",
                            title="Broken Authentication",
                            severity="critical",
                            description="Protected endpoint accessible without authentication",
                            endpoint=endpoint,
                            evidence=f"HTTP {response.status_code} - Protected resource accessible without auth token",
                            recommendation="Require valid authentication tokens for all protected endpoints"
                        )
                        self.vulnerabilities.append(vuln)
                        return
                    
                    # Test with invalid token
                    fake_token = "invalid_token_12345"
                    fake_headers = {**self.get_headers(), "Authorization": f"Bearer {fake_token}"}
                    response_fake = await self.client.get(full_url, headers=fake_headers)
                    self.requests_sent += 1
                    
                    if response_fake.status_code == 200:
                        vuln = Vulnerability(
                            id="API2:2023",
                            title="Broken Authentication",
                            severity="critical",
                            description="Protected endpoint accepts invalid authentication tokens",
                            endpoint=endpoint,
                            evidence=f"HTTP {response_fake.status_code} - Invalid token accepted",
                            recommendation="Implement proper token validation and verification"
                        )
                        self.vulnerabilities.append(vuln)
                        return
                except:
                    pass
        except Exception as e:
            print(f"Authentication test error: {e}")
    
    async def test_injection(self):
        """Test for SQL Injection and Command Injection (REAL)"""
        try:
            search_endpoints = [
                "/api/search",
                "/api/query",
                "/search",
                "/api/users",
                "/api/data"
            ]
            
            all_payloads = SQL_INJECTION_PAYLOADS + COMMAND_INJECTION_PAYLOADS
            self.payloads_generated = len(all_payloads)
            
            for endpoint in search_endpoints:
                for payload in all_payloads:
                    try:
                        # Test query parameter injection
                        full_url = urljoin(self.target_url, f"{endpoint}?q={payload}")
                        response = await self.client.get(full_url, headers=self.get_headers())
                        self.requests_sent += 1
                        
                        # Look for injection indicators in response
                        response_text = response.text.lower()
                        sql_errors = [
                            "sql syntax", "mysql", "postgresql", "sqlite", 
                            "ora-", "syntax error", "unclosed quotation",
                            "quoted string not properly terminated"
                        ]
                        
                        command_errors = [
                            "sh: ", "bash: ", "command not found",
                            "/bin/sh", "permission denied"
                        ]
                        
                        for error in sql_errors:
                            if error in response_text:
                                vuln = Vulnerability(
                                    id="API8:2023",
                                    title="SQL Injection Vulnerability",
                                    severity="critical",
                                    description="Endpoint vulnerable to SQL injection attacks",
                                    endpoint=f"{endpoint}?q={payload[:20]}...",
                                    evidence=f"SQL error detected in response: '{error}' found in output",
                                    recommendation="Use parameterized queries and input validation"
                                )
                                self.vulnerabilities.append(vuln)
                                return
                        
                        for error in command_errors:
                            if error in response_text:
                                vuln = Vulnerability(
                                    id="API8:2023",
                                    title="Command Injection Vulnerability",
                                    severity="critical",
                                    description="Endpoint vulnerable to command injection",
                                    endpoint=f"{endpoint}?q={payload[:20]}...",
                                    evidence=f"Command execution detected: '{error}' in response",
                                    recommendation="Never pass user input directly to system commands"
                                )
                                self.vulnerabilities.append(vuln)
                                return
                    except:
                        pass
        except Exception as e:
            print(f"Injection test error: {e}")
    
    async def test_rate_limiting(self):
        """Test for Rate Limiting (REAL)"""
        try:
            test_endpoint = "/api/search" if "/api/search" in str(self.target_url) else "/"
            full_url = urljoin(self.target_url, test_endpoint)
            
            # Send 50 rapid requests
            tasks = []
            for i in range(50):
                task = self.client.get(full_url, headers=self.get_headers())
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            self.requests_sent += 50
            
            # Count successful responses
            success_count = 0
            for response in responses:
                if isinstance(response, httpx.Response) and response.status_code == 200:
                    success_count += 1
            
            # If more than 80% succeed, likely no rate limiting
            if success_count > 40:
                vuln = Vulnerability(
                    id="API4:2023",
                    title="Unrestricted Resource Consumption",
                    severity="high",
                    description="No rate limiting detected on API endpoints",
                    endpoint=test_endpoint,
                    evidence=f"{success_count}/50 rapid requests succeeded without throttling",
                    recommendation="Implement rate limiting (e.g., 100 requests per minute per IP)"
                )
                self.vulnerabilities.append(vuln)
        except Exception as e:
            print(f"Rate limiting test error: {e}")
    
    async def test_mass_assignment(self):
        """Test for Mass Assignment (REAL)"""
        try:
            update_endpoints = [
                "/api/users/1",
                "/api/user/1",
                "/api/profile"
            ]
            
            # Attempt to update with privileged fields
            malicious_payloads = [
                {"name": "Test", "isAdmin": True},
                {"name": "Test", "role": "admin"},
                {"name": "Test", "is_admin": True},
                {"name": "Test", "admin": True},
                {"name": "Test", "privileges": "admin"}
            ]
            
            for endpoint in update_endpoints:
                for payload in malicious_payloads:
                    try:
                        full_url = urljoin(self.target_url, endpoint)
                        
                        # Try PATCH request
                        response = await self.client.patch(
                            full_url,
                            json=payload,
                            headers=self.get_headers()
                        )
                        self.requests_sent += 1
                        
                        if response.status_code in [200, 201]:
                            response_data = response.json() if response.text else {}
                            
                            # Check if privileged field was accepted
                            for priv_field in ["isAdmin", "role", "is_admin", "admin", "privileges"]:
                                if priv_field in response_data:
                                    vuln = Vulnerability(
                                        id="API3:2023",
                                        title="Broken Object Property Level Authorization",
                                        severity="high",
                                        description="Mass assignment allows modification of privileged fields",
                                        endpoint=endpoint,
                                        evidence=f"Privileged field '{priv_field}' accepted in update request",
                                        recommendation="Whitelist allowed fields and reject privileged field updates"
                                    )
                                    self.vulnerabilities.append(vuln)
                                    return
                    except:
                        pass
        except Exception as e:
            print(f"Mass assignment test error: {e}")
    
    async def test_information_disclosure(self):
        """Test for Information Disclosure (REAL)"""
        try:
            # Try to trigger errors to see if sensitive info is disclosed
            error_endpoints = [
                "/api/nonexistent",
                "/api/users/99999",
                "/api/error"
            ]
            
            for endpoint in error_endpoints:
                try:
                    full_url = urljoin(self.target_url, endpoint)
                    response = await self.client.get(full_url, headers=self.get_headers())
                    self.requests_sent += 1
                    
                    response_text = response.text.lower()
                    
                    # Check for sensitive information in error messages
                    sensitive_patterns = [
                        "stack trace", "traceback", "exception",
                        "file not found: /", "error in /",
                        "database error", "sql error",
                        "api key", "secret", "password",
                        ".env", "config"
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in response_text:
                            vuln = Vulnerability(
                                id="API8:2023",
                                title="Security Misconfiguration - Information Disclosure",
                                severity="medium",
                                description="Error messages expose sensitive system information",
                                endpoint=endpoint,
                                evidence=f"Sensitive pattern '{pattern}' found in error response",
                                recommendation="Use generic error messages in production and disable debug mode"
                            )
                            self.vulnerabilities.append(vuln)
                            return
                except:
                    pass
        except Exception as e:
            print(f"Information disclosure test error: {e}")
    
    async def run_all_tests(self):
        """Execute all security tests"""
        print(f"Starting scan on: {self.target_url}")
        
        try:
            # Discover endpoints first
            await self.discover_endpoints()
            
            # Run all tests concurrently
            await asyncio.gather(
                self.test_bola(),
                self.test_authentication(),
                self.test_injection(),
                self.test_rate_limiting(),
                self.test_mass_assignment(),
                self.test_information_disclosure(),
                return_exceptions=True
            )
        finally:
            await self.client.aclose()
        
        return self.vulnerabilities

@app.post("/api/scan", response_model=ScanResult)
async def create_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Initiate a new REAL security scan"""
    scan_id = str(uuid.uuid4())
    start_time = datetime.now()
    
    # Create real security tester
    tester = RealSecurityTester(
        scan_request.target_url,
        scan_request.api_type,
        scan_request.auth_token
    )
    
    # Run actual security tests
    vulnerabilities = await tester.run_all_tests()
    
    # Calculate statistics
    summary = {
        "total": len(vulnerabilities),
        "critical": sum(1 for v in vulnerabilities if v.severity == "critical"),
        "high": sum(1 for v in vulnerabilities if v.severity == "high"),
        "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
        "low": sum(1 for v in vulnerabilities if v.severity == "low"),
        "info": sum(1 for v in vulnerabilities if v.severity == "info")
    }
    
    duration = (datetime.now() - start_time).total_seconds()
    
    result = ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now().isoformat(),
        target=str(scan_request.target_url),
        api_type=scan_request.api_type,
        duration=f"{duration:.1f}s",
        summary=summary,
        vulnerabilities=vulnerabilities,
        endpoints_tested=tester.endpoints_tested,
        requests_sent=tester.requests_sent,
        payloads_generated=tester.payloads_generated
    )
    
    scans_db[scan_id] = result
    return result

@app.get("/api/scans")
async def get_scans():
    """Retrieve all scan results"""
    return list(scans_db.values())

@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    """Retrieve a specific scan result"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_db[scan_id]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
ENDOFFILE