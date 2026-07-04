#!/bin/bash

echo "🚀 Starting build process..."

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser for crawling
echo "📦 Installing Playwright Chromium..."
playwright install chromium

# Verify installation
echo "✅ Playwright version:"
playwright --version

echo "✅ Build completed successfully!"