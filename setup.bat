@echo off
REM PHISHNET - Windows Setup Script

echo 🧠 PHISHNET - AI Cybersecurity Suite Setup
echo ==========================================

REM Check for Python
echo 🐍 Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is required but not installed.
    pause
    exit /b 1
)
echo ✅ Python found

REM Check for Node.js
echo 🟢 Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is required but not installed.
    pause
    exit /b 1
)
echo ✅ Node.js found

REM Setup Backend
echo.
echo 🔧 Setting up Backend (FastAPI)...
cd backend

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo 📦 Creating Python virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo 🔋 Activating virtual environment...
call venv\Scripts\activate

REM Install Python dependencies
echo 📚 Installing Python dependencies...
pip install -r requirements.txt

REM Copy environment file
if not exist ".env" (
    echo ⚙️ Creating environment file...
    copy .env.example .env
    echo 📝 Please edit backend\.env with your API keys and configuration
)

REM Create directories
echo 📁 Creating necessary directories...
mkdir uploads 2>nul
mkdir logs 2>nul
mkdir ai_models\cache 2>nul

cd ..

REM Setup Frontend
echo.
echo 🎨 Setting up Frontend (Next.js)...
cd frontend

REM Install Node.js dependencies
echo 📦 Installing Node.js dependencies...
npm install

REM Copy environment file
if not exist ".env.local" (
    echo ⚙️ Creating frontend environment file...
    copy .env.example .env.local
)

cd ..

echo.
echo 🎉 Setup Complete!
echo.
echo 🚀 Quick Start Commands:
echo   Backend:  cd backend ^&^& venv\Scripts\activate ^&^& uvicorn main:app --reload
echo   Frontend: cd frontend ^&^& npm run dev
echo.
echo 🌐 URLs:
echo   Frontend: http://localhost:3000
echo   Backend:  http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
echo ⚠️  Don't forget to:
echo    1. Edit backend\.env with your API keys
echo    2. Edit frontend\.env.local if needed
echo.
echo 📖 See README.md for detailed documentation
pause