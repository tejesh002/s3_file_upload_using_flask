# S3 FILE UPLOAD USING FLASK

A Flask web application for user registration, login, and file uploads to AWS S3, with admin and user roles.

## Features
- User registration and login
- Admin and user roles (admin can see all uploads, users see only their own)
- File upload (max 10MB) to AWS S3
- File listing dashboard
- Flash messages for feedback

## Tech Stack
- Python 3.8+
- Flask
- Flask-SQLAlchemy
- AWS S3 (for file storage)
- SQLite (for local DB)
- Bootstrap (for UI)

## Setup Instructions

### 1. Clone the repository
```bash
git clone <repo-url>
cd s3_file_upload_using_flask
```

### 2. Create a Python virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
Create a `.env` file in the root directory with the following content:
```
SECRET_KEY=your_secret_key
S3_BUCKET=your_s3_bucket_name
S3_REGION=your_s3_region
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
```

### 5. Run the application
```bash
python app.py
```
The app will be available at http://127.0.0.1:5000/

## Default Admin User
- Email: `admin@example.com`
- Password: `admin123`

## Usage
- Register a new user or login as admin.
- Upload files (max 10MB, stored on S3).
- Admin can see all uploads; users see only their own.

## File Structure
- `app.py` - Main Flask app
- `requirements.txt` - Python dependencies
- `templates/` - HTML templates (login, register, dashboard)

## License
MIT
