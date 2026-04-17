# SentinelGuard AI - Quick Setup Guide

## ⚡ 5-Minute Setup

### Prerequisites
- Node.js 18+ (`node -v`)
- Python 3.9+ (`python --version`)
- MongoDB Atlas account (free tier works)

### Step 1: Clone & Install Frontend
```bash
cd SentinelGuard-AI
npm install
```

### Step 2: Setup Backend
```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Create .env file with your MongoDB URI
echo "MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/?appName=Cluster0" > .env
echo "MONGO_DB_NAME=sentinelguard_ai" >> .env
echo "JWT_SECRET_KEY=your-secret-key-change-in-production" >> .env
```

### Step 3: Train ML Model (Optional, ~30 seconds)
```bash
python ml/train_model.py
```

### Step 4: Start Both Servers

**Terminal 1 - Frontend:**
```bash
cd SentinelGuard-AI
npm run dev
# Frontend: http://localhost:3000
```

**Terminal 2 - Backend:**
```bash
cd SentinelGuard-AI/backend
python app.py
# Backend: http://localhost:5000
```

### Step 5: Access the App
- Open http://localhost:3000
- Sign up with any email and password (6+ chars)
- Start analyzing phishing threats!

---

## 🔑 Test Credentials

After signup:
```
Email: user@example.com
Password: password123
```

Admin account (auto-created if you use this email):
```
Email: admin@sentinelguard.ai
Password: admin123
```

Then:
1. Login to user account
2. Go to Dashboard
3. Click "Open admin dashboard" link
4. You can access both dashboards!

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `backend/.env` | Database & JWT config |
| `backend/requirements.txt` | Python dependencies |
| `package.json` | Node.js dependencies |
| `lib/auth.ts` | JWT token management |
| `PROJECT_STRUCTURE.md` | Full project layout |
| `ARCHITECTURE.md` | Data flow diagrams |

---

## 🚀 What to Try First

1. **Sign Up**: Create a new account
2. **Analyze**: On home page, paste an email or URL
3. **View Results**: Check Dashboard for your scan history
4. **Admin Dashboard**: Login as admin@sentinelguard.ai to see all data

---

## 🔧 Troubleshooting

### "Cannot connect to backend"
- Ensure `http://localhost:5000` backend is running
- Check CORS in `backend/app.py` (should allow localhost:3000)

### "MongoDB connection failed"
- Verify `MONGO_URI` in `backend/.env`
- Check IP whitelist in MongoDB Atlas (add 0.0.0.0/0 for local dev)
- Test connection: `python -c "from pymongo import MongoClient; MongoClient('YOUR_URI').admin.command('ping')"`

### "JWT token invalid"
- Clear browser localStorage (`F12` → Application → localStorage → clear)
- Log out and log back in
- Check `JWT_SECRET_KEY` in `.env` (must match frontend)

### "Port already in use"
- Frontend: Change port in `npm run dev`
- Backend: Change port in `backend/app.py` (line: `app.run(port=5001)`)
- Then update `API_BASE_URL` in `lib/auth.ts`

### "ML Model not found"
- Run: `cd backend && python ml/train_model.py`
- Wait for "Model trained and saved" message

---

## 📊 Example Phishing Detection

**Input:**
```
Email: "Click here to verify your account immediately"
URL: "https://bank-login-verify-secure.com"
```

**Expected Output:**
```
Status: Phishing
Confidence: 92%
Message: High-confidence phishing indicators were detected.
```

---

## 🔐 Security Notes

- Never commit `.env` files (already in .gitignore)
- Change `JWT_SECRET_KEY` for production
- Don't expose `MONGO_URI` with credentials publicly
- For production, use environment variables instead of `.env`

---

## 🆘 Need Help?

1. Check [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for full layout
2. See [ARCHITECTURE.md](ARCHITECTURE.md) for data flows
3. Review [README.md](README.md) for full documentation
4. Check backend logs: any errors printed to console

---

## ✅ Verification Checklist

- [ ] Frontend runs at http://localhost:3000
- [ ] Backend runs at http://localhost:5000
- [ ] Can sign up and log in
- [ ] Dashboard shows scan history
- [ ] Can analyze emails/URLs
- [ ] Results appear in dashboard after scan
- [ ] Admin account can access admin dashboard

---

**You're all set! Start detecting phishing threats! 🎯**
