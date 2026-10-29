# CheckMyCode — Project Security & Deployment Readiness Platform

> **Find the risks. Fix them before you ship.**  
> Scan your project for potential security vulnerabilities, exposed secrets, risky configurations, and dependency advisories before deployment.

CheckMyCode (formerly OpenGuard) is an offline-capable, developer-focused static code security analyzer. It inspects source code, configurations, and dependency manifests without running compilers, executing arbitrary code, or transmitting data to third-party AI APIs.

---

## 🏛️ Architecture Overview

The application has been migrated to a modern, production-minded decoupled architecture:

```
CheckMyCode/
├── backend/                  # FastAPI Application
│   └── app/
│       ├── main.py           # FastAPI app & endpoint routing
│       ├── schemas/          # Pydantic v2 data models
│       └── services/         # Scanner orchestration & report services
├── frontend/                 # Next.js 15 App Router Frontend
│   ├── app/
│   │   ├── page.tsx          # Homepage with Hero, How It Works & Capabilities
│   │   ├── scan/page.tsx     # Drag-and-drop ZIP upload with preferences
│   │   ├── results/page.tsx  # Structured findings, filtering, downloads & feedback
│   │   ├── terms/page.tsx    # Dedicated Terms & Conditions page
│   │   └── privacy/page.tsx  # Dedicated Privacy Policy page
│   ├── components/layout/    # Responsive Navbar & Footer
│   ├── lib/                  # Typed API client, models & utilities
│   └── public/               # CheckMyCode logo, icon, and favicon
├── modules/                  # Core Python Security Scanning Engine
│   ├── archive_handler.py    # Safe archive validation & zip-slip protection
│   ├── secret_scanner.py     # High-entropy & regex secret detection
│   ├── security_scanner.py   # Code pattern analysis (eval, shell=True, etc.)
│   ├── dependency_scanner.py # CVE advisory matching for requirements.txt & package.json
│   ├── configuration_scanner.py # Dockerfile & docker-compose misconfig checks
│   ├── risk_scorer.py        # Readiness evaluation scoring algorithm
│   └── report_generator.py   # Standalone HTML & JSON report generation
├── tests/                    # Pytest test suite (31 unit tests)
└── sample_data/              # Sample microservice for testing
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+** (Python 3.13 tested)
- **Node.js 18+** (Node v20.18 included in `tools/node-v20.18.0-win-x64`)

---

### 1. Running the FastAPI Backend

```bash
# Activate your Python virtual environment
.\.venv\Scripts\activate

# Install dependencies (if not already installed)
pip install fastapi uvicorn pydantic python-multipart httpx

# Start the FastAPI server
python -m uvicorn backend.app.main:app --port 8000 --host 127.0.0.1 --reload
```

The backend will be available at:
- **API URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`

---

### 2. Running the Next.js Frontend

```bash
cd frontend

# Set the path to Node (or use system Node)
$env:PATH = "D:\Projects\OpenGuard\tools\node-v20.18.0-win-x64;" + $env:PATH

# Development server
npm run dev

# Or Production build & run
npm run build
npm run start -- -p 3000
```

The frontend will be available at:
- **Web App**: `http://localhost:3000`

---

## 🛡️ Security & Privacy Guarantees

1. **Zero Code Execution**: Uploaded source files are parsed purely via AST and static regex checks.
2. **Volatile Isolation**: Files are extracted to a randomized temporary directory with zip-slip path traversal guards and deleted immediately upon completion.
3. **No External AI APIs**: Code and secrets never leave your local environment.
4. **Secret Masking**: Sensitive keys (AWS, OpenAI, GitHub, database URIs) are automatically masked in browser views and downloaded reports.
5. **No Telemetry**: No third-party tracking pixels or analytics cookies.

---

## 🧪 Testing

```bash
# Run backend pytest test suite
.\.venv\Scripts\python.exe -m pytest tests/ -v

# Run Next.js production build check
cd frontend
npm run build
```
