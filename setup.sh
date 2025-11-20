#!/bin/bash

# PHISHNET - Quick Setup Script
# This script sets up both frontend and backend environments

echo "🧠 PHISHNET - AI Cybersecurity Suite Setup"
echo "=========================================="

# Check for Python
echo "🐍 Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi
echo "✅ Python 3 found"

# Check for Node.js
echo "🟢 Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi
echo "✅ Node.js found"

# Setup Backend
echo ""
echo "🔧 Setting up Backend (FastAPI)..."
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔋 Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Copy environment file
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment file..."
    cp .env.example .env
    echo "📝 Please edit backend/.env with your API keys and configuration"
fi

# Create directories
echo "📁 Creating necessary directories..."
mkdir -p uploads logs ai_models/cache

cd ..

# Setup Frontend
echo ""
echo "🎨 Setting up Frontend (Next.js)..."
cd frontend

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Copy environment file
if [ ! -f ".env.local" ]; then
    echo "⚙️ Creating frontend environment file..."
    cp .env.example .env.local
fi

cd ..

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "🚀 Quick Start Commands:"
echo "  Backend:  cd backend && source venv/bin/activate && uvicorn main:app --reload"
echo "  Frontend: cd frontend && npm run dev"
echo ""
echo "🌐 URLs:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "⚠️  Don't forget to:"
echo "   1. Edit backend/.env with your API keys"
echo "   2. Edit frontend/.env.local if needed"
echo ""
echo "📖 See README.md for detailed documentation"