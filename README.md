# Inventory Management System

Flask + Firebase Firestore inventory management with Bootstrap 5 UI.

## Setup

### 1. Firebase Setup

1. Go to https://console.firebase.google.com/
2. Create a new project (or select existing)
3. Go to **Project Settings** → **Service Accounts** → **Generate New Private Key**
4. Download the JSON key file
5. Save as `private/firebase-key.json`

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Set Environment Variable

Set `FIREBASE_SERVICE_ACCOUNT` to the raw JSON string, OR place your key file at `private/firebase-key.json`.

### 4. Run

```bash
python app.py
```

Default login: `admin` / `admin123`

## Deployment

### Render

1. Push to GitHub
2. On Render, create a new **Web Service**
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add `FIREBASE_SERVICE_ACCOUNT` as a secret env var (paste the full service account JSON)
6. Add `SECRET_KEY` env var

## Default Credentials

- **Username:** admin
- **Password:** admin123
- **Role:** admin

## Sample Data

Visit `/seed-sample` endpoint after login to populate sample products and shops.
