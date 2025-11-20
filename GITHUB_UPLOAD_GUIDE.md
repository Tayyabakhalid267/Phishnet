# 📤 GitHub Upload Guide

## Step-by-Step Instructions to Upload PHISHNET to GitHub

### Prerequisites
✅ Git installed on your computer  
✅ GitHub account created  
✅ All files ready in your project directory

---

## Method 1: Using Command Line (Recommended)

### Step 1: Initialize Git Repository

Open PowerShell in your project directory and run:

```powershell
# Navigate to project directory
cd C:\Users\khant\OneDrive\Desktop\Phisnet

# Initialize git repository
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit: PHISHNET AI Cybersecurity Suite"
```

### Step 2: Create GitHub Repository

1. Go to https://github.com/new
2. Fill in the details:
   - **Repository name:** `phishnet`
   - **Description:** "AI-Powered Cybersecurity Suite for Phishing Detection & Analysis"
   - **Visibility:** Choose Public or Private
   - ⚠️ **DO NOT** initialize with README, .gitignore, or license (we already have these)
3. Click **Create repository**

### Step 3: Connect and Push to GitHub

Copy the repository URL from GitHub (looks like: `https://github.com/YOUR_USERNAME/phishnet.git`)

Run these commands:

```powershell
# Add remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/phishnet.git

# Rename branch to main (if needed)
git branch -M main

# Push to GitHub
git push -u origin main
```

**If asked for credentials:**
- Username: Your GitHub username
- Password: Use a Personal Access Token (not your GitHub password)

### Step 4: Create Personal Access Token (if needed)

If you need a token:

1. Go to https://github.com/settings/tokens
2. Click **Generate new token** → **Generate new token (classic)**
3. Name it: "PHISHNET Upload"
4. Check: `repo` (full control of private repositories)
5. Click **Generate token**
6. Copy the token (you won't see it again!)
7. Use this token as your password when pushing

### Step 5: Verify Upload

1. Go to your GitHub repository: `https://github.com/YOUR_USERNAME/phishnet`
2. Check that all files are uploaded
3. README should display automatically

---

## Method 2: Using GitHub Desktop (Easier for Beginners)

### Step 1: Install GitHub Desktop
Download from: https://desktop.github.com/

### Step 2: Sign in to GitHub
- Open GitHub Desktop
- Click **File** → **Options** → **Accounts**
- Sign in with your GitHub credentials

### Step 3: Add Repository
1. Click **File** → **Add Local Repository**
2. Click **Choose...** and select: `C:\Users\khant\OneDrive\Desktop\Phisnet`
3. Click **create a repository** (if prompted)
4. Leave default settings and click **Create Repository**

### Step 4: Publish to GitHub
1. Click **Publish repository** button
2. Enter details:
   - Name: `phishnet`
   - Description: "AI-Powered Cybersecurity Suite"
   - Choose Public or Private
3. Click **Publish Repository**

### Step 5: Verify
Open in browser: `https://github.com/YOUR_USERNAME/phishnet`

---

## Method 3: Using VS Code (If you have VS Code)

### Step 1: Open Project in VS Code
```powershell
cd C:\Users\khant\OneDrive\Desktop\Phisnet
code .
```

### Step 2: Initialize Git
1. Click **Source Control** icon (left sidebar)
2. Click **Initialize Repository**
3. Add commit message: "Initial commit"
4. Click ✓ checkmark to commit

### Step 3: Publish to GitHub
1. Click **Publish to GitHub** button
2. Choose repository name: `phishnet`
3. Select Public or Private
4. Click **Publish**

---

## Post-Upload Steps

### 1. Update README with Your GitHub Username

Edit `README.md` and replace:
- `YOUR_USERNAME` with your actual GitHub username
- Update the Railway deploy button URL

### 2. Add Repository Topics (Optional but Recommended)

On GitHub repository page:
1. Click ⚙️ Settings gear next to About
2. Add topics: `cybersecurity`, `phishing-detection`, `ai`, `fastapi`, `nextjs`, `python`, `typescript`, `railway`, `security`
3. Click **Save changes**

### 3. Enable GitHub Pages (Optional)

To host documentation:
1. Go to Settings → Pages
2. Source: Deploy from branch
3. Branch: main → /docs
4. Click Save

### 4. Add Repository Description

On main page, click ⚙️ and add:
> AI-Powered Cybersecurity Suite for Phishing Detection & Analysis - Real-time threat intelligence, ML-based detection, and enterprise-grade security

### 5. Star Your Own Repo! ⭐

Give yourself the first star!

---

## Quick Reference Commands

```powershell
# Check git status
git status

# See commit history
git log --oneline

# Push new changes
git add .
git commit -m "Description of changes"
git push

# Pull latest changes
git pull

# Create new branch
git checkout -b feature/new-feature

# Switch branches
git checkout main
```

---

## Troubleshooting

### Error: "fatal: not a git repository"
```powershell
git init
```

### Error: "remote origin already exists"
```powershell
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/phishnet.git
```

### Error: "failed to push some refs"
```powershell
git pull origin main --rebase
git push -u origin main
```

### Large files warning
Git doesn't like files > 100MB. If you have large ML models:
```powershell
# Install Git LFS
git lfs install
git lfs track "*.model"
git lfs track "*.bin"
git add .gitattributes
git commit -m "Add Git LFS tracking"
```

### Authentication Issues
Use Personal Access Token instead of password:
1. Generate token at https://github.com/settings/tokens
2. Use token as password when prompted

---

## Next Steps After Upload

1. ✅ Repository is live on GitHub
2. 🚀 Deploy to Railway using the GitHub integration
3. 📝 Add detailed issue templates
4. 🔄 Set up CI/CD (already configured in `.github/workflows/ci.yml`)
5. 📊 Enable Dependabot for security updates
6. 🎯 Create first release/tag
7. 📢 Share your project!

---

## Making Your First Release

```powershell
# Tag the release
git tag -a v1.0.0 -m "Initial release - PHISHNET v1.0.0"

# Push the tag
git push origin v1.0.0
```

Then on GitHub:
1. Go to **Releases**
2. Click **Draft a new release**
3. Choose tag: v1.0.0
4. Title: "PHISHNET v1.0.0 - Initial Release"
5. Describe features and changes
6. Click **Publish release**

---

## Repository Best Practices

✅ Keep README updated  
✅ Write clear commit messages  
✅ Use branches for new features  
✅ Review code before merging  
✅ Keep dependencies updated  
✅ Respond to issues and PRs  
✅ Document major changes  
✅ Tag releases properly  

---

**Your PHISHNET project will be live on GitHub!** 🎉

Repository URL will be:
```
https://github.com/YOUR_USERNAME/phishnet
```

Good luck! 🚀
