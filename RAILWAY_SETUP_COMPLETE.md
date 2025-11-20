# 🚂 Railway Deployment - Files Created

## Overview
Your PHISHNET project is now ready for Railway.app deployment. All necessary configuration files have been created.

## Files Created

### 1. Core Configuration Files

#### `railway.json`
- Railway platform configuration
- Specifies Nixpacks builder
- Configures restart policies

#### `Procfile`
- Defines how to start the backend service
- Command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

#### `nixpacks.toml`
- Build configuration for Railway
- Installs Python 3.11 and Node.js 18
- Builds both backend and frontend

#### `requirements.txt` (root)
- Python dependencies for backend
- Includes FastAPI, ML libraries, and security packages

#### `runtime.txt`
- Specifies Python version: 3.11.6

### 2. Backend Configuration

#### `backend/config.py`
- Environment-aware settings
- Handles production and development configurations
- Manages CORS origins dynamically
- Supports database and Redis URLs

Updated `backend/main.py`:
- Imports settings from config
- Dynamic CORS configuration
- Production-ready

### 3. Frontend Configuration

#### `frontend/next.config.production.js`
- Production optimizations
- Standalone output for Railway
- Environment variable handling
- Console removal in production

### 4. Environment & Security

#### `.env.example`
- Template for environment variables
- Lists all required configuration
- Security reminders

#### `.gitignore`
- Excludes sensitive files
- Ignores node_modules, venv, cache
- Keeps repository clean

#### `.railwayignore`
- Files to exclude from Railway deployment
- Removes debug and test files

### 5. Documentation

#### `RAILWAY_DEPLOYMENT.md`
- Complete step-by-step deployment guide
- Environment variable configuration
- Troubleshooting section
- Cost estimation
- Security checklist

#### `DEPLOYMENT.md`
- Quick start guide
- Alternative deployment methods (VPS, Docker)
- Post-deployment checklist
- Monitoring instructions

---

## Quick Deployment Steps

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Ready for Railway deployment"
git remote add origin https://github.com/YOUR_USERNAME/phishnet.git
git push -u origin main
```

### 2. Deploy Backend on Railway
1. Go to https://railway.app/new
2. Select "Deploy from GitHub repo"
3. Choose your phishnet repository
4. Add environment variables:
   ```
   ENVIRONMENT=production
   SECRET_KEY=your-random-32-char-secret
   JWT_SECRET=your-random-32-char-jwt-secret
   CORS_ORIGINS=https://your-frontend.railway.app
   ```
5. Deploy and copy the backend URL

### 3. Deploy Frontend on Railway
1. In same project, add new service
2. Select same GitHub repository
3. Set root directory: `frontend`
4. Add environment variable:
   ```
   NEXT_PUBLIC_API_URL=https://your-backend.railway.app
   ```
5. Deploy and copy frontend URL

### 4. Update Backend CORS
- Go back to backend service
- Update `CORS_ORIGINS` with the frontend URL
- Railway auto-redeploys

### 5. Test Your Deployment
- Visit your frontend URL
- Login with: Mubashar / Mubashar9266
- Test scan features
- Check admin panel

---

## Environment Variables Needed

### Backend Service
```env
ENVIRONMENT=production
PORT=8000
SECRET_KEY=<generate-random-string>
JWT_SECRET=<generate-random-string>
CORS_ORIGINS=https://your-frontend.railway.app,http://localhost:3000
```

### Frontend Service
```env
NODE_VERSION=18
NEXT_PUBLIC_API_URL=https://your-backend.railway.app
NEXT_PUBLIC_WS_URL=wss://your-backend.railway.app
```

### Optional (for full features)
```env
DATABASE_URL=postgresql://...      # If using PostgreSQL
REDIS_URL=redis://...              # If using Redis
OPENAI_API_KEY=sk-...              # If using OpenAI
HUGGINGFACE_TOKEN=hf_...           # If using HuggingFace
MAX_WORKERS=4
```

---

## Generate Secure Secrets

Use Python to generate random secrets:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Or use online generator (but change immediately):
https://randomkeygen.com/

---

## Cost Estimation

### Railway Free Tier
- $5 credit = ~500 execution hours/month
- Good for: Testing and development

### Railway Starter ($5/month)
- $5 credit + pay for overages
- Good for: Small production apps, personal projects

### Railway Pro ($20/month)
- 8GB RAM, faster builds
- Good for: ML workloads, PHISHNET with full AI features

**Note**: ML libraries (PyTorch, Transformers) require more memory.
Recommend Pro plan if using all AI features.

---

## Architecture on Railway

```
Railway Project: PHISHNET
│
├── Service 1: Backend (FastAPI)
│   ├── Port: 8000 (auto-assigned by Railway)
│   ├── URL: https://phishnet-backend-xxx.railway.app
│   └── Build: Python 3.11 + ML libraries
│
├── Service 2: Frontend (Next.js)
│   ├── Port: 3000 (auto-assigned by Railway)
│   ├── URL: https://phishnet-frontend-xxx.railway.app
│   └── Build: Node.js 18 + Next.js build
│
└── Optional Plugins:
    ├── PostgreSQL (if needed)
    └── Redis (if needed)
```

---

## Next Steps

1. **Review RAILWAY_DEPLOYMENT.md** for detailed instructions
2. **Create GitHub repository** and push code
3. **Sign up for Railway** at https://railway.app
4. **Follow deployment steps** above
5. **Configure environment variables**
6. **Test your deployment**
7. **Set up custom domain** (optional)

---

## Troubleshooting

### Build Timeout or Out of Memory
- ML libraries are large (~2-3GB)
- Solution: Remove unused ML deps or upgrade to Pro plan

### CORS Errors
- Verify CORS_ORIGINS includes your frontend URL
- Must use HTTPS in production
- Check for trailing slashes

### Frontend Can't Connect to Backend
- Verify NEXT_PUBLIC_API_URL is correct
- Check both services are deployed
- Look at logs in Railway dashboard

### Database Connection Issues
- Ensure DATABASE_URL is set correctly
- Railway auto-provides this when you add PostgreSQL plugin

---

## Support Resources

- **Railway Docs**: https://docs.railway.app
- **Railway Discord**: https://discord.gg/railway
- **Railway Templates**: https://railway.app/templates
- **Status Page**: https://status.railway.app

---

## Security Reminders

✅ Change all default passwords and secrets  
✅ Use strong random strings for SECRET_KEY and JWT_SECRET  
✅ Never commit .env files to git  
✅ Enable HTTPS only (Railway does this by default)  
✅ Configure proper CORS origins  
✅ Set up rate limiting in production  
✅ Monitor logs for suspicious activity  
✅ Keep dependencies updated  

---

**Your PHISHNET project is now Railway-ready!** 🎉

Total deployment time: ~15-20 minutes  
Difficulty: Beginner-friendly  
Free tier: Available for testing
