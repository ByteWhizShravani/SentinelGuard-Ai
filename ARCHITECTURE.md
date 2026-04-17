# SentinelGuard AI - Architecture & Data Flow

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React/Next.js)                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Auth Pages   │  │   Dashboard  │  │   Admin Dashboard    │  │
│  │ (Login/Signup│  │ (Scan Results│  │  (All Scans/Users)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         ↓                ↓                     ↓                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │        Detection Form (Phishing Analysis)               │  │
│  └──────────────────────────────────────────────────────────┘  │
│              ↓                            ↓                     │
│       [JWT Token]                   [Auto-Refresh Event]       │
└─────────────────────────────────────────────────────────────────┘
              ↓                                    ↓
        Authorization: Bearer <token>     Window Event Listener
              ↓                                    ↓
┌─────────────────────────────────────────────────────────────────┐
│              BACKEND (Flask REST API)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ /auth/login  │  │ /analyze     │  │ /scan-results/history│  │
│  │ /auth/signup │  │ (Protected)  │  │ (Protected)          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│              ↓                                    ↓               │
│       [JWT Validation]                    [Get User Email]      │
│              ↓                                    ↓               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              ML Model Prediction                         │  │
│  │  (TF-IDF Vectorizer + Logistic Regression)              │  │
│  │  Input: email_text, url                                 │  │
│  │  Output: {status, confidence, message}                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│              ↓                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │            MongoDB Database                              │  │
│  │  Collections: users, scan_results                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Authentication Flow

```
1. SIGNUP
   User Input (email, password)
     ↓
   Validate Email & Password Format
     ↓
   Hash Password (bcrypt)
     ↓
   Create User in MongoDB
     ↓
   Return Success Message
     ↓
   Redirect to Login

2. LOGIN
   User Input (email, password)
     ↓
   Find User in MongoDB
     ↓
   Verify Password (bcrypt.checkpw)
     ↓
   Extract Role from Database
     ↓
   Create JWT Token (24-hour expiry)
     ↓
   Return Token + User Info
     ↓
   Store Token in localStorage (Frontend)
     ↓
   Set Cookie auth_role (for middleware)
     ↓
   Redirect to Dashboard
```

## Phishing Detection Flow

```
User enters email text and/or URL
     ↓
Frontend sends to POST /analyze
     ↓
JWT Middleware validates token
     ↓
Backend receives email & URL
     ↓
ML Model Prediction:
   ├─ Convert text to TF-IDF vector
   ├─ Run through Logistic Regression
   ├─ Get probability & class
   └─ Generate confidence score
     ↓
Classify Result:
   ├─ Phishing (confidence ≥ 75%) → "Phishing" + message
   ├─ Phishing (confidence < 75%) → "Suspicious" + message
   ├─ Safe (confidence ≥ 60%) → "Safe" + message
   └─ Safe (confidence < 60%) → "Suspicious" + review hint
     ↓
Save to MongoDB scan_results
   ├─ email
   ├─ url
   ├─ result {status, confidence, message}
   └─ timestamp
     ↓
Return result to Frontend
     ↓
Frontend emits 'scanCompleted' event
     ↓
Dashboard receives event → Refreshes table
```

## Data Models

### User Document
```
{
  _id: ObjectId,
  email: "user@example.com",
  password_hash: "$2b$12$...",
  role: "user|admin",
  created_at: "2025-04-17T10:00:00Z",
  updated_at: "2025-04-17T10:00:00Z"
}
```

### Scan Result Document
```
{
  _id: ObjectId,
  email: "user@example.com",
  url: "https://suspicious-login.com",
  result: {
    status: "Phishing|Safe|Suspicious",
    confidence: 92,
    message: "High-confidence phishing indicators detected"
  },
  timestamp: "2025-04-17T10:05:00Z"
}
```

## API Request/Response Examples

### Login Request
```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

### Login Response (200)
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "email": "user@example.com",
    "role": "user"
  }
}
```

### Analyze Request
```bash
POST /analyze
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "email": "Click here to verify your account",
  "url": "https://secure-bank-login-verify.com"
}
```

### Analyze Response (200)
```json
{
  "status": "Phishing",
  "confidence": 92,
  "message": "High-confidence phishing indicators were detected.",
  "prediction": "Phishing"
}
```

### Scan History Request
```bash
GET /scan-results/history?limit=100
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Scan History Response (200)
```json
{
  "count": 5,
  "items": [
    {
      "id": "507f1f77bcf86cd799439011",
      "email": "test@phishing.com",
      "url": "https://malicious-site.com",
      "result": {
        "status": "Phishing",
        "confidence": 92,
        "message": "..."
      },
      "timestamp": "2025-04-17T10:05:00Z"
    },
    ...
  ]
}
```

## Protected Routes

### Frontend Routes (Middleware)
- `/dashboard` - Requires valid JWT token
- `/admin` - Requires valid JWT token + admin role

### Backend Routes (JWT Required)
- `POST /analyze`
- `POST /scan-results`
- `GET /scan-results/history`
- `GET /users`

### Public Routes
- `GET /health`
- `POST /auth/login`
- `POST /auth/signup`

## Error Handling

### 401 Unauthorized
```json
{
  "message": "Invalid credentials."
}
```

### 403 Forbidden
```json
{
  "message": "Admin access required."
}
```

### 400 Bad Request
```json
{
  "message": "Enter a valid email address."
}
```

## Performance Considerations

- **JWT Caching**: Tokens cached in localStorage, no server-side session storage
- **ML Model**: Pre-trained on startup, predictions in <100ms
- **Database Indexes**: 
  - `scan_results.timestamp` (sort efficiency)
  - `scan_results.email` (filter by user)
  - `users.email` (unique, login lookups)
- **CORS**: Only frontend origin allowed for API calls
- **Rate Limiting**: Recommended for production

## Deployment Checklist

- [ ] Update `JWT_SECRET_KEY` in backend/.env
- [ ] Update `MONGO_URI` for production database
- [ ] Configure CORS for production frontend domain
- [ ] Set `NODE_ENV=production` for Next.js
- [ ] Use HTTPS for all connections
- [ ] Enable password reset functionality
- [ ] Add rate limiting middleware
- [ ] Set up monitoring and logging
- [ ] Create backup strategy for MongoDB
- [ ] Test all authentication flows
