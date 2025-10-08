# React Frontend for DNS Dashboard

## Setup
1. Install Node.js and npm if not already installed.
2. Run the following commands:
```
cd dashboard/react-frontend
npm install
npm start
```

## Features
- View DNS traffic statistics
- View alerts and blocked domains
- Auto-refresh every 10 seconds

## API Endpoints
- `/api/dns-stats`
- `/api/alerts`
- `/api/blocked`

## Note
Ensure the Flask backend is running on port 5000 before starting the frontend.
