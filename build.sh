#!/bin/bash

echo "🚀 Installing dependencies..."

# Upgrade pip
pip install --upgrade pip

# Install wheel dan Cython versi lama (kompatibel)
pip install wheel cython==0.29.37

# Install scikit-learn dengan --no-build-isolation
pip install --no-build-isolation scikit-learn==1.0.2

# Install XGBoost versi stabil
pip install xgboost==1.7.6

# Install sisanya
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

echo "✅ Build completed!"