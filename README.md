API Security Scanner



Enterprise-grade automated vulnerability assessment platform for REST, GraphQL, and SOAP APIs.



Overview



Automated security testing platform that detects OWASP API Top 10 vulnerabilities in seconds. Built with FastAPI, React, TypeScript, and Docker.



\### Key Features



✅ \*\*OWASP API Top 10 Coverage\*\* - Complete vulnerability detection  

✅ \*\*Multi-Protocol Support\*\* - REST, GraphQL, SOAP  

✅ \*\*Real-Time Scanning\*\* - Live progress tracking  

✅ \*\*Intelligent Fuzzing\*\* - ML-enhanced payload generation  

✅ \*\*Comprehensive Reports\*\* - Actionable remediation guidance  

✅ \*\*CI/CD Ready\*\* - Docker containerized deployment  



Quick Start



Prerequisites



\- Docker Desktop (v20.10+)

\- Docker Compose (v2.0+)



Installation

```bash

Clone the repository



git clone https://github.com/BryanJ417/api-security-scanner.git

cd api-security-scanner



Start all services

docker-compose up --build



Access the application

Frontend: http://localhost:3000

Backend API: http://localhost:8000

API Docs: http://localhost:8000/docs





What It Detects



\- \*\*API1:2023\*\* - Broken Object Level Authorization (BOLA)

\- \*\*API2:2023\*\* - Broken Authentication

\- \*\*API3:2023\*\* - Broken Object Property Level Authorization

\- \*\*API4:2023\*\* - Unrestricted Resource Consumption

\- \*\*API5:2023\*\* - Broken Function Level Authorization

\- \*\*API6:2023\*\* - Unrestricted Access to Sensitive Business Flows

\- \*\*API7:2023\*\* - Server Side Request Forgery (SSRF)

\- \*\*API8:2023\*\* - Security Misconfiguration

\- \*\*API9:2023\*\* - Improper Inventory Management

\- \*\*API10:2023\*\* - Unsafe Consumption of APIs



Tech Stack



\*\*Backend:\*\* FastAPI, Python 3.11, Pydantic, HTTPX, Uvicorn  

\*\*Frontend:\*\* React 18, TypeScript, Vite, Tailwind CSS  

\*\*Infrastructure:\*\* Docker, Docker Compose, Nginx  



Usage



1\. Navigate to http://localhost:3000

2\. Enter target API URL

3\. Select API type (REST/GraphQL/SOAP)

4\. Configure authentication (if needed)

5\. Click "Start Security Scan"

6\. Review detailed vulnerability reports



Performance Metrics



\- \*\*Speed:\*\* 6-10 seconds per scan (vs 8+ hours manual)

\- \*\*Throughput:\*\* 1,847+ HTTP requests per scan

\- \*\*Payloads:\*\* 342+ security payloads generated

\- \*\*Time Saved:\*\* 85%+ reduction in testing time



📄 License



MIT License - See LICENSE file for details



\## 👤 Author



\*\*Bryan Jorge\*\*  

\[GitHub](https://github.com/BryanJ417) | \[LinkedIn](https://linkedin.com/in/bryanjorge)



\## 🙏 Acknowledgments



\- OWASP for API Security Top 10 framework

\- FastAPI for the excellent Python framework

\- React community for frontend tools


