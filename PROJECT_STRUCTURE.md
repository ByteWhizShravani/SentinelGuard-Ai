# SentinelGuard AI - Final Project Structure

## Overview
A full-stack phishing detection system with React frontend, Flask backend, scikit-learn ML model, and MongoDB database.

```
SentinelGuard-AI/
├── app/                           # Next.js App Router pages
│   ├── login/
│   │   └── page.tsx              # Login page with JWT auth flow
│   ├── signup/
│   │   └── page.tsx              # Signup page
│   ├── dashboard/
│   │   └── page.tsx              # Protected user dashboard with scan history
│   ├── admin/
│   │   └── page.tsx              # Protected admin dashboard (admin-only)
│   ├── layout.tsx                # Root layout with metadata
│   ├── page.tsx                  # Home page
│   └── globals.css               # Global styles
│
├── components/                    # Reusable React components
│   ├── auth-form.tsx             # Login/signup form with Flask backend integration
│   ├── detection-form.tsx        # Phishing analysis form (calls /analyze API)
│   ├── detection-lifecycle.tsx   # Process diagram component
│   ├── protected-route.tsx       # Route guard for authenticated pages
│   ├── features-section.tsx      # Landing page section
│   ├── hero-section.tsx          # Hero banner
│   ├── monitoring-dashboard.tsx  # Stats display
│   ├── navbar.tsx                # Navigation bar
│   ├── team-section.tsx          # Team info
│   └── footer.tsx                # Footer
│
├── lib/                           # Utilities and helpers
│   └── auth.ts                   # JWT token management, auth state, API headers
│
├── backend/                       # Flask REST API
│   ├── app.py                    # Flask app initialization with JWT support
│   ├── .env                      # Environment variables (MONGO_URI, JWT_SECRET_KEY)
│   ├── requirements.txt          # Python dependencies
│   │
│   ├── routes/                   # API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py               # POST /auth/login, POST /auth/signup
│   │   ├── analyze.py            # POST /analyze (JWT-protected)
│   │   ├── scan_results.py       # POST /scan-results, GET /scan-results/history (JWT-protected)
│   │   └── users.py              # GET /users (JWT-protected)
│   │
│   ├── auth/                     # Authentication utilities
│   │   ├── __init__.py
│   │   └── security.py           # password hashing (bcrypt), verification
│   │
│   ├── db/                       # Database layer
│   │   ├── __init__.py
│   │   └── mongo.py              # MongoDB connection, CRUD operations
│   │                             # Collections: users, scan_results
│   │
│   ├── ml/                       # Machine learning models
│   │   ├── __init__.py
│   │   ├── model.py              # Scikit-learn pipeline (TF-IDF + Logistic Regression)
│   │   ├── train_model.py        # Model training script
│   │   ├── placeholder.py        # Rule-based fallback analyzer
│   │   └── phishing_model.pkl    # Trained model artifact (pickle)
│   │
│   └── data/
│       └── phishing_dataset.csv  # Training dataset (20 samples)
│
├── public/                        # Static assets
│   └── assets/
│
├── lib/                           # Frontend utilities
│   └── auth.ts                   # JWT token & session management
│
├── middleware.ts                 # Next.js route protection middleware
├── tsconfig.json                 # TypeScript configuration
├── tailwind.config.ts            # Tailwind CSS configuration
├── next.config.mjs               # Next.js configuration
├── package.json                  # Frontend dependencies
├── DESIGN.md                     # Design documentation
└── README.md                     # (Create as needed)
```

## Technology Stack

### Frontend (React + Next.js)
- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: React Hooks
- **Auth**: JWT tokens stored in localStorage

### Backend (Flask)
- **Framework**: Flask
- **Authentication**: Flask-JWT-Extended
- **Database Driver**: PyMongo
- **Security**: bcrypt for password hashing
- **CORS**: Flask-CORS for frontend integration

### Machine Learning
- **Framework**: scikit-learn
- **Vectorizer**: TF-IDF
- **Model**: Logistic Regression
- **Serialization**: pickle

### Database
- **Platform**: MongoDB Atlas (Cloud)
- **Collections**:
  - `users`: email, password_hash, role, created_at, updated_at
  - `scan_results`: email, url, result, timestamp

## Key Features

### Authentication & Authorization
- User signup and login with bcrypt password hashing
- JWT token generation and validation (24-hour expiry)
- Role-based access control (user, admin)
- Protected routes on frontend and backend

### Phishing Detection
- Input: Email text and/or URL
- ML Model: TF-IDF vectorization + Logistic Regression
- Output: Phishing/Safe status with confidence score
- Fallback: Rule-based suspicious keyword detection

### User Dashboard
- View personal scan history
- Live statistics (total scans, phishing count, suspicious count)
- Auto-refresh after new scans
- JWT-protected API calls

### Admin Dashboard
- View all users
- View all scan results
- Filter by status (Safe/Phishing/Suspicious)
- User and scan analytics

## API Endpoints

### Public
- `GET /health` - Health check

### Auth (No JWT required)
- `POST /auth/signup` - Register new user
- `POST /auth/login` - Get JWT token

### Protected (JWT required)
- `POST /analyze` - Run phishing detection
- `POST /scan-results` - Save scan result
- `GET /scan-results/history` - Fetch user's scan history
- `GET /users` - Fetch all users (admin only via role check)

## Development Setup

### Prerequisites
- Node.js 18+
- Python 3.9+
- MongoDB Atlas account

### Install & Run

**Frontend:**
```bash
npm install
npm run dev
# Runs on http://localhost:3000
```

**Backend:**
```bash
cd backend
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

**Train ML Model:**
```bash
cd backend
python ml/train_model.py
```

## Database Collections

### users
```json
{
  "_id": ObjectId,
  "email": "user@example.com",
  "password_hash": "bcrypt_hash",
  "role": "user|admin",
  "created_at": "2025-04-17T10:00:00Z",
  "updated_at": "2025-04-17T10:00:00Z"
}
```

### scan_results
```json
{
  "_id": ObjectId,
  "email": "user@example.com",
  "url": "https://example.com",
  "result": {
    "status": "Phishing|Safe|Suspicious",
    "confidence": 92,
    "message": "High-confidence phishing indicators..."
  },
  "timestamp": "2025-04-17T10:05:00Z"
}
```

## Environment Variables

**Backend (.env)**
```
MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/?appName=Cluster0
MONGO_DB_NAME=sentinelguard_ai
JWT_SECRET_KEY=your-secret-key-here
```

**Frontend (lib/auth.ts)**
```
API_BASE_URL=http://localhost:5000
```

## Data Flow

1. **User Registration**: Signup → Hash password → Store in MongoDB
2. **User Login**: Verify credentials → Generate JWT → Return token
3. **Phishing Detection**: 
   - Send email/URL with Bearer token
   - ML model predicts
   - Save result to MongoDB
   - Return prediction
4. **View History**: Dashboard fetches scan results → Display with statistics
5. **Auto-refresh**: Detection form emits event → Dashboard listener → Refresh table

## Security Features

- JWT authentication on all protected endpoints
- Password hashing with bcrypt
- CORS configured for frontend origin
- Route protection on both frontend (middleware) and backend
- Role-based admin access
- Secure token storage in localStorage
- HTTP-only considerations for production

## Future Enhancements

- Add refresh token rotation
- Implement email verification for signup
- Add password reset functionality
- Expand ML model with more training data
- Add real-time WebSocket notifications
- Implement rate limiting on API endpoints
- Add audit logging for admin actions
- Deploy to production (Vercel for frontend, Heroku/AWS for backend)
