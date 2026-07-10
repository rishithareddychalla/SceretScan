# SecretScan: Multi-Challenge Unified Submission

SecretScan is an enterprise-grade security scanner and interactive dashboard designed to detect and remediate hardcoded secrets (such as API keys, private keys, database connection URIs, and authorization tokens) in active code files, ZIP archives, and Git history. 

This repository serves as a double-submission for:
1. **Security & Secrets Scanner Challenge**: Detection, active credential verification, pre-commit hook blockages, and AI-driven remediation.
2. **Containerization & Docker Challenge**: Fully optimized, lightweight Docker container and Docker Compose orchestrations with volume mounting.

---

## Key Capabilities & Features

### 🛡️ Challenge 1: Security Secret Scanner
* **Deep Scanning Engine**: Scans active workspace files and walks Git commit history (analyzing historical commits for deleted/modified secrets).
* **Smart Detection Rules**: Powered by custom high-entropy filters and granular regex rules for AWS, GCP, Azure, Slack, Stripe, OpenAI, Gemini, and general auth tokens.
* **Active Status Verification**: Live validation checks that test detected keys against active authentication servers to determine if the keys are live or revoked.
* **Developer Shield (Pre-Commit Hook)**: Custom Git hook installation (`sentinel.py install-hook`) that intercepts commits and blocks them if secrets are detected.
* **AI Remediation Assistant**: Seamlessly integrates with Gemini/OpenAI to generate custom explanations, risk ratings, and replacement instructions for developers.
* **Compare Snapshots**: Compares a new scan against a past snapshot (`compare` command) to check for introduced or resolved leaks.
* **Watch Mode**: Real-time daemon (`--watch` flag) that monitors file changes and alerts developers of leaks as they edit.

### 🐳 Challenge 2: Containerization & Dockerization
* **Lightweight Footprint**: Built on `python:3.11-slim` with temporary layer cleanups, keeping build times and image sizes minimal.
* **Automated Package Management**: Bundles python dependencies and handles system-level packages (such as `git` for commit analysis).
* **Strict Docker Ignore Rules**: Utilizes `.dockerignore` to filter out local virtual environments, test suites, database caches, and local configuration files.
* **Docker Compose Orchestration**: Configured to run the web server on port `5000` with native bind-mount support to dynamically scan codebases on the host machine.
* **Environment Variable Support**: Fully configurable via a `.env` template supporting customizable port, host, and AI provider parameters.

---

## Tech Stack

* **Core Language & CLI**: Python 3.11, Git CLI, Shannon Entropy Algorithms.
* **Web Server Backend**: Flask, Gunicorn (production server inside container).
* **Interactive Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (Glassmorphism layout), Chart.js (severity & category analytics), Google Fonts (Outfit & JetBrains Mono), FontAwesome.
* **Orchestration & Tooling**: Docker, Docker Compose.

---

## Configuration & Environment Setup

Create a `.env` file in the root directory to store your environment variables:

```ini
# Port binding for the Flask server (0.0.0.0 is required for Docker)
HOST=0.0.0.0
PORT=5000

# LLM API keys for the AI Remediation features (Optional)
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

---

## Building and Running (Docker Challenge)

### Method 1: Using Docker Compose (Recommended)
Docker Compose automatically builds the environment, maps port `5000`, loads the `.env` parameters, and mounts the current directory inside the container for active scanning.

1. **Start the application**:
   ```bash
   docker-compose up --build -d
   ```
2. **Access the Web Dashboard**:
   Open [http://localhost:5000](http://localhost:5000) in your web browser.
3. **Stop the application**:
   ```bash
   docker-compose down
   ```

### Method 2: Using Raw Docker CLI
1. **Build the Image**:
   ```bash
   docker build -t secretscan-app .
   ```
2. **Run the Container**:
   * **Linux / macOS**:
     ```bash
     docker run -d \
       -p 5000:5000 \
       --env-file .env \
       -v "$(pwd):/app" \
       --name secretscan \
       secretscan-app
     ```
   * **Windows (PowerShell)**:
     ```powershell
     docker run -d `
       -p 5000:5000 `
       --env-file .env `
       -v "${PWD}:/app" `
       --name secretscan `
       secretscan-app
     ```

---

## CLI & Scanner Commands (Security Scanner Challenge)

You can run the scanner via the command line. If using the local setup, run `python sentinel.py <command>`. If using Docker, run `docker exec -it secretscan-dashboard python sentinel.py <command>`.

### 1. Scan Commands
* **Scan current directory**:
  ```bash
  python sentinel.py scan
  ```
* **Scan a specific file or folder**:
  ```bash
  python sentinel.py scan /path/to/target
  ```
* **Scan a remote GitHub Repository**:
  ```bash
  python sentinel.py scan https://github.com/user/repo --github
  ```
* **Scan a ZIP archive**:
  ```bash
  python sentinel.py scan project.zip --zip
  ```
* **Enable Watch Mode (monitor files as you edit)**:
  ```bash
  python sentinel.py scan -w
  ```
* **Export report to JSON, HTML, or SARIF formats**:
  ```bash
  python sentinel.py scan --format html --output-file report.html
  python sentinel.py scan --format sarif --output-file report.sarif
  ```

### 2. Safeguard & Git Configurations
* **Install Git Pre-Commit Hook**:
  Installs a local pre-commit hook that automatically blocks commits containing leaks before they reach Git history.
  ```bash
  python sentinel.py install-hook
  ```
* **Audit and Fix Gitignore rules**:
  Identifies sensitive files (such as `.env`, `.pem` files, `.db`) that are not ignored in your `.gitignore` and auto-appends them.
  ```bash
  python sentinel.py fix gitignore
  ```

### 3. Analytics & History Auditing
* **Compare against Snapshot**:
  ```bash
  python sentinel.py compare past_snapshot.json
  ```
* **Export GitHub Action template**:
  ```bash
  python sentinel.py export-ci
  ```

---

## CI/CD Workflow & SARIF Reports

The repository includes a modern GitHub Actions pipeline located in `.github/workflows/sentinel.yml`.
* **Automatic Security Scans**: Automatically runs on every `push` and `pull_request` to the main branch.
* **SARIF Integration**: Generates a standard `sentinel-report.sarif` file and uploads it to GitHub Code Scanning, allowing security alerts to render directly in your GitHub Security tab.
* **Auto-pages deployment**: Automatically packages and deploys a styled security report dashboard to GitHub Pages on successful workflows.
