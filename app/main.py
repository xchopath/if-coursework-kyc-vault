from flask import Flask, render_template, request, redirect, send_file, abort, Response, flash
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
from crypto_utils import generate_key, encrypt_file, decrypt_file
from io import BytesIO
import os
import uuid
import mimetypes

UPLOAD_FOLDER = '/app/uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Setup DB
engine = create_engine('postgresql://postgres:postgres@db:5432/kycdb')
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

# DB Model
class KYCFile(Base):
    __tablename__ = 'kyc_files'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    filename = Column(String)
    filepath = Column(String)
    encryption_key = Column(String)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# Auth Protection

USERNAME = 'cs'
PASSWORD = 'Secure@2025!'

def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    return Response(
        'Akses ditolak.\nGunakan username dan password yang benar.', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_basic_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload():
    name = request.form.get('name')
    uploaded_file = request.files['file']
    if uploaded_file:
        original_filename = secure_filename(uploaded_file.filename)
        filename_ = os.path.splitext(original_filename)[0]
        ext = os.path.splitext(original_filename)[1]
        random_name = f"{uuid.uuid4().hex}{ext}"
        filename = secure_filename(random_name)

        raw_data = uploaded_file.read()
        key = generate_key()
        encrypted_data = encrypt_file(raw_data, key)

        # Save encrypted file
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{filename}')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        # Save metadata to DB
        kyc_file = KYCFile(
            name=name,
            filename=filename,
            filepath=encrypted_path,
            encryption_key=key.decode()
        )
        session.add(kyc_file)
        session.commit()

    flash('The file has been successfully uploaded and encrypted securely!', 'success')
    return redirect('/')

@app.route('/manage/secure_open')
@requires_basic_auth
def secure_open():
    file_id = request.args.get('file_id')
    if not file_id:
        return "file_id is required", 400

    file_record = session.query(KYCFile).filter_by(id=file_id).first()
    if not file_record or not os.path.exists(file_record.filepath):
        return abort(404)

    # Baca dan dekripsi file
    with open(file_record.filepath, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt_file(encrypted_data, file_record.encryption_key.encode())
    except Exception as e:
        return f"Failed to decrypt: {str(e)}", 500

    # Guess MIME type
    mime_type, _ = mimetypes.guess_type(file_record.filename)
    mime_type = mime_type or 'application/octet-stream'

    return send_file(BytesIO(decrypted_data), download_name=file_record.filename, mimetype=mime_type)

@app.route('/manage')
@requires_basic_auth
def list_files():
    files = session.query(KYCFile).order_by(KYCFile.uploaded_at.desc()).all()
    return render_template('manage_list.html', files=files)

if __name__ == '__main__':
    app.secret_key = '18ab08e5208dc0b388e4aaf422191ee2668e2a6163022ae55251afce1f83a66c5fd40c05ccbf41688eb2214dfbd6a0dc3783b90e016156be3d169fd44c223371'
    app.run(host='0.0.0.0')
