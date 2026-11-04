# ==============================================================================
# Enterprise People & Compliance AI - Cloud Container Image
# Multi-arch Linux container running Microsoft PowerShell LTS
# ==============================================================================
FROM mcr.microsoft.com/powershell:lts-alpine

# Set working directory
WORKDIR /app

# Copy application assets, data schemas, frontend, and backend
COPY . .

# Cloud platforms (Render, Railway, Cloud Run) assign dynamic PORT environment variable
ENV PORT=3865

# Expose default port
EXPOSE 3865

# Start the enterprise server
CMD ["pwsh", "-File", "./server.ps1"]
