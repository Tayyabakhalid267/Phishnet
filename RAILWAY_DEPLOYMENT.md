# 🚂 Railway.app Deployment Guide for PHISHNET

## Prerequisites
- GitHub account
- Railway.app account (sign up at https://railway.app)
- Git installed locally

## Step 1: Prepare Your Repository

### 1.1 Initialize Git (if not already done)
```bash
git init
git add .
git commit -m "Initial commit for Railway deployment"
```

### 1.2 Create GitHub Repository
1. Go to https://github.com/new
2. Create a new repository named `phishnet`
3. Push your code:
```bash
git remote add origin https://github.com/YOUR_USERNAME/phishnet.git
git branch -M main
git push -u origin main
```

## Step 2: Deploy Backend on Railway

### 2.1 Create New Project
1. Go to https://railway.app/dashboard
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Authorize Railway to access your GitHub
5. Select your `phishnet` repository

### 2.2 Configure Backend Service
1. Railway will auto-detect the Python app
2. Add environment variables in Railway dashboard:

**Required Environment Variables:**
```
PORT=8000
PYTHON_VERSION=3.11.6
ENVIRONMENT=production
CORS_ORIGINS=https://YOUR_FRONTEND_URL.railway.app,http://localhost:3000
SECRET_KEY=your-super-secret-key-change-this
JWT_SECRET=your-jwt-secret-key-change-this
DATABASE_URL=your-postgres-url (if using database)
REDIS_URL=your-redis-url (if using Redis)
```

**Optional AI/ML Variables:**
```
OPENAI_API_KEY=your-openai-key (if using OpenAI)
HUGGINGFACE_TOKEN=your-hf-token (if using HuggingFace models)
MAX_WORKERS=4
```

### 2.3 Set Build & Start Commands
Railway should auto-detect from `Procfile`, but verify:
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

### 2.4 Deploy Backend
1. Click "Deploy"
2. Wait for deployment (5-10 minutes for first deploy with ML libraries)
3. Copy the generated URL: `https://your-app-name.railway.app`

## Step 3: Deploy Frontend on Railway

### 3.1 Add New Service to Project
1. In the same Railway project, click "New Service"
2. Select "Deploy from GitHub repo"
3. Select your `phishnet` repository again
4. Railway will create a second service

### 3.2 Configure Frontend Service
Add environment variables:
```
NODE_VERSION=18
NEXT_PUBLIC_API_URL=https://YOUR_BACKEND_URL.railway.app
NEXT_PUBLIC_WS_URL=wss://YOUR_BACKEND_URL.railway.app
```

### 3.3 Set Frontend Build Commands
In Railway settings for frontend service:
- **Root Directory**: `frontend`
- **Build Command**: `npm install && npm run build`
- **Start Command**: `npm start`
- **Port**: `3000` (Railway will auto-assign)

### 3.4 Deploy Frontend
1. Click "Deploy"
2. Wait for build and deployment
3. Copy the generated URL: `https://your-frontend.railway.app`

## Step 4: Update CORS Settings

### 4.1 Update Backend CORS
Go back to backend service and update `CORS_ORIGINS`:
```
CORS_ORIGINS=https://your-frontend.railway.app,http://localhost:3000
```

### 4.2 Redeploy Backend
Railway will auto-redeploy when you change environment variables.

## Step 5: Optional - Add Database (PostgreSQL)

### 5.1 Add PostgreSQL Plugin
1. In Railway project, click "New"
2. Select "Database" → "PostgreSQL"
3. Railway will provision a database and provide connection URL

### 5.2 Update Backend Environment Variables
Railway automatically adds `DATABASE_URL` variable.

### 5.3 Run Database Migrations (if needed)
Use Railway's CLI or connect via the dashboard to run:
```bash
alembic upgrade head
```

## Step 6: Optional - Add Redis

### 6.1 Add Redis Plugin
1. Click "New" → "Database" → "Redis"
2. Railway provisions Redis instance
3. `REDIS_URL` is automatically added

## Step 7: Monitoring & Logs

### 7.1 View Logs
- Click on each service to view real-time logs
- Check for errors during deployment

### 7.2 Monitor Resources
- Railway dashboard shows CPU, Memory, and Network usage
- Free tier: 500 hours/month ($5 credit)

## Step 8: Custom Domain (Optional)

### 8.1 Add Custom Domain
1. Go to service settings
2. Click "Settings" → "Domains"
3. Click "Add Custom Domain"
4. Follow DNS configuration instructions

## Deployment Architecture

```
┌─────────────────────────────────────────┐
│         Railway Project: PHISHNET       │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   Frontend Service (Next.js)    │   │
│  │   Port: 3000                     │   │
│  │   URL: frontend.railway.app     │   │
│  └─────────────────────────────────┘   │
│              │                          │
│              │ API Calls                │
│              ▼                          │
│  ┌─────────────────────────────────┐   │
│  │   Backend Service (FastAPI)     │   │
│  │   Port: 8000                     │   │
│  │   URL: backend.railway.app      │   │
│  └─────────────────────────────────┘   │
│              │                          │
│              ├─────────┬──────────┐     │
│              ▼         ▼          ▼     │
│         ┌────────┐ ┌──────┐  ┌──────┐  │
│         │  Redis │ │ PG   │  │ ML   │  │
│         │  Cache │ │ DB   │  │Models│  │
│         └────────┘ └──────┘  └──────┘  │
└─────────────────────────────────────────┘
```

## Troubleshooting

### Build Fails - Out of Memory
ML libraries (PyTorch, Transformers) are large:
- Remove unused ML libraries from `requirements.txt`
- Or upgrade to Railway Pro plan (8GB RAM)

### Build Timeout
- Split dependencies into smaller chunks
- Use pre-built wheels
- Consider Railway Pro for faster builds

### CORS Errors
- Verify `CORS_ORIGINS` includes frontend URL
- Check frontend is using correct `NEXT_PUBLIC_API_URL`
- Both must use HTTPS in production

### WebSocket Connection Fails
- Ensure `NEXT_PUBLIC_WS_URL` uses `wss://` not `ws://`
- Check Railway firewall settings

### Environment Variables Not Working
- Restart service after changing variables
- Check variable names match code exactly
- No trailing spaces in variable values

## Cost Estimation

**Free Tier:**
- $5 credit = ~500 execution hours/month
- Enough for development and testing

**Starter Plan ($5/month):**
- $5 credit + overages
- Good for small production apps

**Pro Plan ($20/month):**
- 8GB RAM, faster builds
- Better for ML workloads

## Next Steps After Deployment

1. **Set up monitoring**: Add logging service (Sentry, LogRocket)
2. **Configure CI/CD**: Auto-deploy on git push
3. **Add health checks**: Monitor uptime
4. **Enable backups**: For database
5. **Set up alerts**: For errors and downtime
6. **Add authentication**: Secure admin endpoints
7. **Enable rate limiting**: Prevent abuse
8. **Add analytics**: Track usage

## Railway CLI (Optional)

Install Railway CLI for advanced features:
```bash
npm i -g @railway/cli
railway login
railway link
railway logs
railway run python manage.py migrate
```

## Support & Resources

- **Railway Docs**: https://docs.railway.app
- **Discord**: https://discord.gg/railway
- **Status**: https://status.railway.app
- **Pricing**: https://railway.app/pricing

## Security Checklist

- [ ] Change all default passwords and secrets
- [ ] Set strong `SECRET_KEY` and `JWT_SECRET`
- [ ] Enable HTTPS only (Railway does this by default)
- [ ] Configure proper CORS origins
- [ ] Add rate limiting to API endpoints
- [ ] Use environment variables for all secrets
- [ ] Enable Railway's built-in DDoS protection
- [ ] Set up database backups
- [ ] Monitor logs for suspicious activity
- [ ] Keep dependencies updated

---

**Deployment Time**: 15-30 minutes  
**Difficulty**: Intermediate  
**Cost**: Free tier available, Pro plan recommended for ML workloads
