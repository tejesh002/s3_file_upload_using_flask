import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import boto3
from botocore.exceptions import BotoCoreError, NoCredentialsError
from dotenv import load_dotenv
from botocore.client import Config
from io import BytesIO


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB upload limit

db = SQLAlchemy(app)

# AWS S3 Config
S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION")
S3_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
S3_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(10))  # ADMIN or USER

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_url = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='files')

# Create tables and default admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(
            name='Admin',
            email='admin@example.com',
            password=generate_password_hash('admin123'),
            role='ADMIN'
        )
        db.session.add(admin)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = 'USER'
        try:
            new_user = User(name=name, email=email, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Registered successfully! Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Error during registration: " + str(e), "danger")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['role'] = user.role
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            s3_key = f"{user.name}_{user.id}/{filename}"
            try:
                s3_client = boto3.client(
                    's3',
                    region_name=S3_REGION,
                    aws_access_key_id=S3_ACCESS_KEY,
                    aws_secret_access_key=S3_SECRET_KEY,
                    config=Config(signature_version='s3v4')
                )

                s3_client.upload_fileobj(
                    file,
                    S3_BUCKET,
                    s3_key,
                )
                file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
                new_file = File(file_url=file_url, user_id=user.id)
                db.session.add(new_file)
                db.session.commit()
                flash("File uploaded successfully!", "success")
            except (BotoCoreError, NoCredentialsError, ClientError) as e:
                error_msg = str(e)
                if "signature" in error_msg.lower():
                    flash("AWS authentication error. Please check your credentials and region.", "danger")
                elif "credentials" in error_msg.lower():
                    flash("AWS credentials not found or invalid.", "danger")
                else:
                    flash("Failed to upload file to S3: " + error_msg, "danger")

    if user.role == 'ADMIN':
        files = File.query.all()
    else:
        files = File.query.filter_by(user_id=user.id).all()

    return render_template('dashboard.html', user=user, files=files)

@app.route('/download/<filename>')
def download_file(filename):
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash('You must be logged in to download files.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('dashboard'))
        s3_key = f"{user.name}_{user.id}/{filename}"
        s3_client = boto3.client(
            's3',
            region_name=S3_REGION,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            config=Config(signature_version='s3v4')
        )
        file_stream = BytesIO()
        s3_client.download_fileobj(S3_BUCKET, s3_key, file_stream)
        file_stream.seek(0)
        return send_file(file_stream, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f"Error generating download link: {e}", "danger")
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
