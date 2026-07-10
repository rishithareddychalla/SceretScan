# Base Python image
FROM python:3.11-slim

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install git since SentinelScan relies on git history scanning via GitPython
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . /app/

# Expose port 5000 for the Flask Web UI
EXPOSE 5000

# Start Flask web application (defaulting to host 0.0.0.0 for docker ingress)
CMD ["python", "web_ui.py"]
