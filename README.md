# SentinelScan: Web Security Dashboard & Secret Scanner

SentinelScan is a premium, containerized security scanning platform designed to detect hardcoded secrets (such as API keys, private keys, database connection URIs, and authorization tokens) in active code files and Git history. It features a fully responsive, glassmorphic interactive web dashboard and automated remediation tools.

---

## Features

- **Multi-Source Scanner**: Analyzes both live workspace files and historical Git commits.
- **Security Scorecard**: Computes a dynamic security grade (A–F) based on leak severity weights.
- **Visual Analytics**: Interactive doughnut and bar charts visualizing leak categories and severity distribution.
- **AI Remediation Assistant**: Integrates with LLMs to automatically generate explanations and code fixes for detected leaks.
- **Pre-Commit Shield**: Installs local hooks to block developers from accidentally committing secrets.
- **CI/CD Integration**: Fully compatible with GitHub Actions, generating SARIF outputs for GitHub Code Scanning and auto-deploying dashboards to GitHub Pages.

---

## Prerequisites

- [Docker](https://www.docker.com/) (version 20.10 or later)
- [Docker Compose](https://docs.docker.com/compose/) (optional, recommended)

---

## Configuration & Environment Variables

Create a `.env` file in the root directory to store your environment variables:

```ini
# Port binding for the Flask server (use 0.0.0.0 for Docker ingress)
HOST=0.0.0.0

# LLM API keys for the AI Remediation and Explanation features
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

---

## Building and Running the Application

### Method 1: Using Docker Compose (Recommended)

Docker Compose automatically configures port mappings, environment variables, and mounts your local workspace directory so that the scanner can analyze your local codebase:

1. **Start the application**:
   ```bash
   docker-compose up --build
   ```
2. **Access the Web Dashboard**:
   Open [http://localhost:5000](http://localhost:5000) in your web browser.
3. **Stop the application**:
   ```bash
   docker-compose down
   ```

### Method 2: Using Raw Docker CLI

1. **Build the Docker Image**:
   ```bash
   docker build -t sentinelscan-app .
   ```
2. **Run the Container**:
   - On **Linux / macOS**:
     ```bash
     docker run -d \
       -p 5000:5000 \
       --env-file .env \
       -v "$(pwd):/app" \
       --name sentinelscan \
       sentinelscan-app
     ```
   - On **Windows (PowerShell)**:
     ```powershell
     docker run -d `
       -p 5000:5000 `
       --env-file .env `
       -v "${PWD}:/app" `
       --name sentinelscan `
       sentinelscan-app
     ```

---

## How It's Containerized (Optimizations)

- **Lightweight Base Image**: Uses `python:3.11-slim` to reduce package footprint and keep the image size minimal.
- **System Dependencies**: Automatically installs Git (`git`) since the backend relies on checking Git repository commits.
- **Port Exposure**: Exposes port `5000` for Flask web server access.
- **Docker Ignore (`.dockerignore`)**: Excludes development assets (`.git`, `__pycache__`, `.pytest_cache/`, `tests/`) and local secrets (`.env`) to ensure maximum build speed and security.
- **Volume Mounting**: Mounts the host directory to `/app` inside the container, allowing the scanner to analyze local repositories dynamically without needing to rebuild the image.
