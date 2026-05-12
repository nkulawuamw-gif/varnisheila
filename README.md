# Inventory Management System

Flask + Google Sheets inventory management with Bootstrap 5 UI.

## Setup

### 1. Enable Google Sheets API & Create Service Account

1. Go to https://console.cloud.google.com/
2. Create a new project (or select existing)
3. Enable **Google Sheets API** and **Google Drive API**
4. Go to **Credentials** → **Create Credentials** → **Service Account**
5. Give it a name, click Create
6. Click the service account email → **Keys** → **Add Key** → **JSON**
7. Download the JSON key file
8. Rename it to `credentials.json` and place in the project folder

### 2. Share your Google Sheet

1. Run the app once - it will create `InventoryDatabase` automatically
2. Go to https://sheets.google.com/ and open `InventoryDatabase`
3. Click **Share** and add the service account email (from `credentials.json` -> `client_email`) as **Editor**

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

### 4. Run

```bash
python app.py
```

Default login: `admin` / `admin123`

## Deployment

### PythonAnywhere

1. Upload files to PythonAnywhere
2. Create a web app with manual Flask config
3. Set `GOOGLE_CREDENTIALS` env var to full path of credentials.json
4. Set `SECRET_KEY` env var to a random string
5. WSGI config:
```python
import sys
sys.path.insert(0, '/home/yourusername/inventory-management')
from app import app as application
```

### Render

1. Push to GitHub
2. On Render, create a new **Web Service**
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add env vars: `GOOGLE_CREDENTIALS`, `SECRET_KEY`
6. Add credentials.json via Render's secret files or mount it

### Linux Server (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update && sudo apt install python3-pip nginx -y
pip install -r requirements.txt

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app

# Or use systemd + nginx for production
```

## Default Credentials

- **Username:** admin
- **Password:** admin123
- **Role:** admin

## Sample Data

Visit `/seed-sample` endpoint after login to populate sample products.
