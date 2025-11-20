# PHISHNET - Quick Start Deployment

## 🚀 Railway Deployment (Recommended)

### Prerequisites
- GitHub account
- Railway.app account (free tier available)

### Quick Deploy Steps

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial deployment"
   git remote add origin YOUR_GITHUB_URL
   git push -u origin main
   ```

2. **Deploy on Railway**
   - Go to [railway.app](https://railway.app)
   - Click "New Project" → "Deploy from GitHub"
   - Select your repository
   - Railway will auto-detect and deploy

3. **Configure Environment Variables**
   In Railway dashboard, add:
   ```
   ENVIRONMENT=production
   SECRET_KEY=your-random-secret-key
   JWT_SECRET=your-jwt-secret-key
   CORS_ORIGINS=https://your-frontend.railway.app
   ```

4. **Deploy Frontend (Second Service)**
   - Add new service in same project
   - Set root directory to `frontend`
   - Add environment variable:
   ```
   NEXT_PUBLIC_API_URL=https://your-backend.railway.app
   ```

### Total Time: ~15 minutes

---

## Alternative: Traditional VPS Deployment

### Requirements
- Ubuntu/Debian server
- Domain name (optional)
- SSH access

### Installation Script

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11
sudo apt install python3.11 python3.11-venv python3-pip -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y

# Install Nginx
sudo apt install nginx -y

# Clone repository
git clone YOUR_REPO_URL /var/www/phishnet
cd /var/www/phishnet

# Setup backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup frontend
cd frontend
npm install
npm run build

# Configure systemd service
sudo nano /etc/systemd/system/phishnet.service
```

**systemd service file:**
```ini
[Unit]
Description=PHISHNET Backend
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/phishnet
Environment="PATH=/var/www/phishnet/venv/bin"
ExecStart=/var/www/phishnet/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000

[Install]
WantedBy=multi-user.target
```

```bash
# Start services
sudo systemctl enable phishnet
sudo systemctl start phishnet

# Configure Nginx reverse proxy
sudo nano /etc/nginx/sites-available/phishnet
```

**Nginx configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/phishnet /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Docker Deployment (Advanced)

### Create Dockerfile for Backend
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Create Dockerfile for Frontend
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build
CMD ["npm", "start"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=postgresql://...
    
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000
    depends_on:
      - backend
```

Run:
```bash
docker-compose up -d
```

---

## Post-Deployment Checklist

- [ ] Update CORS origins with production URLs
- [ ] Change all default passwords and secrets
- [ ] Set up SSL/HTTPS (Let's Encrypt)
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Enable monitoring and logging
- [ ] Configure rate limiting
- [ ] Test all endpoints
- [ ] Set up CI/CD pipeline
- [ ] Configure domain DNS

---

## Monitoring & Maintenance

### Health Check Endpoints
- Backend: `https://your-api.com/health`
- Frontend: `https://your-app.com`

### View Logs
- **Railway**: Dashboard → Service → Logs tab
- **VPS**: `journalctl -u phishnet -f`
- **Docker**: `docker-compose logs -f`

### Update Application
```bash
git pull origin main
pip install -r requirements.txt
cd frontend && npm install
npm run build
sudo systemctl restart phishnet
```

---

## Support

For detailed Railway deployment instructions, see:
- [RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md)

For issues:
- Check logs first
- Verify environment variables
- Ensure all services are running
- Test network connectivity
