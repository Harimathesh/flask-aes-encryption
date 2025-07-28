import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from io import BytesIO
from PIL import Image
import numpy as np

# Initialize Flask with correct template path
app = Flask(__name__)  # '.' means current directory
app.secret_key = os.urandom(24)

# Mock user database
users = {
    'admin': {'password': 'admin123', 'name': 'Administrator'},
    'user1': {'password': 'password1', 'name': 'Test User'}
}

# AES Functions
def generate_key(key_size=128):
    """Generate key of specified size (128 or 256 bits)"""
    return get_random_bytes(key_size // 8)

def encrypt_text(text, key, key_size=128):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_text(encrypted_text, key):
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def encrypt_image(image_file, key, key_size=128):
    # Save to temporary file first for Vercel compatibility
    temp_path = os.path.join('/tmp', image_file.filename)
    image_file.save(temp_path)
    
    img = Image.open(temp_path)
    img_array = np.array(img)
    
    # Convert image to bytes
    img_bytes = img.tobytes()
    
    # Encrypt the image data
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(img_bytes, AES.block_size))
    iv = cipher.iv
    
    # Combine IV and encrypted data
    encrypted_data = iv + ct_bytes
    
    # Create a new image with encrypted data
    encrypted_img = Image.frombytes(img.mode, img.size, encrypted_data[:len(img_bytes)])
    
    # Clean up temp file
    os.unlink(temp_path)
    
    return encrypted_img, base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_image(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    
    # Reconstruct image from decrypted bytes
    img = Image.frombytes('RGB', (300, 300), pt)  # Adjust size as needed
    return img

# Routes
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    encrypted_result = decrypted_result = encryption_key = None
    image_data = None
    key_size = int(request.form.get('key_size', 128)) if request.method == 'POST' else 128
    
    if request.method == 'POST':
        # Text Encryption/Decryption
        if 'encrypt_text' in request.form:
            text = request.form['text_to_encrypt']
            key = generate_key(key_size)
            encrypted_result = encrypt_text(text, key, key_size)
            encryption_key = base64.b64encode(key).decode('utf-8')
        
        elif 'decrypt_text' in request.form:
            encrypted_text = request.form['encrypted_text']
            key = base64.b64decode(request.form['encryption_key'])
            try:
                decrypted_result = decrypt_text(encrypted_text, key)
            except Exception as e:
                decrypted_result = f"Decryption failed: {str(e)}"
        
        # Image Encryption/Decryption
        elif 'encrypt_image' in request.form and 'image_file' in request.files:
            image_file = request.files['image_file']
            if image_file.filename != '':
                key = generate_key(key_size)
                encrypted_img, image_data = encrypt_image(image_file, key, key_size)
                encryption_key = base64.b64encode(key).decode('utf-8')
                
                # Save encrypted image to temporary file
                img_io = BytesIO()
                encrypted_img.save(img_io, 'PNG')
                session['encrypted_image'] = img_io.getvalue()
        
        elif 'decrypt_image' in request.form:
            encrypted_data = request.form['encrypted_image_data']
            key = base64.b64decode(request.form['image_encryption_key'])
            try:
                decrypted_img = decrypt_image(encrypted_data, key)
                img_io = BytesIO()
                decrypted_img.save(img_io, 'PNG')
                return send_file(
                    img_io,
                    mimetype='image/png',
                    as_attachment=True,
                    download_name='decrypted_image.png'
                )
            except Exception as e:
                flash(f"Image decryption failed: {str(e)}", 'error')
    
    return render_template('index.html',
                         username=session['username'],
                         encrypted_result=encrypted_result,
                         decrypted_result=decrypted_result,
                         encryption_key=encryption_key,
                         image_data=image_data,
                         key_size=key_size)

@app.route('/download_encrypted_image')
def download_encrypted_image():
    if 'encrypted_image' not in session:
        flash('No encrypted image available', 'error')
        return redirect(url_for('index'))
    
    return send_file(
        BytesIO(session['encrypted_image']),
        mimetype='image/png',
        as_attachment=True,
        download_name='encrypted_image.png'
    )

# Vercel serverless handler
def handler(request):
    from werkzeug.wrappers import Request, Response
    
    # Convert Vercel request to Werkzeug request
    environ = {
        'REQUEST_METHOD': request.method,
        'PATH_INFO': request.path,
        'QUERY_STRING': request.query_string,
        'wsgi.input': BytesIO(request.body),
        'wsgi.url_scheme': request.headers.get('X-Forwarded-Proto', 'http'),
        'HTTP_HOST': request.headers.get('host', ''),
    }
    
    # Update with headers
    for key, value in request.headers.items():
        environ[f'HTTP_{key.upper().replace("-", "_")}'] = value
    
    with app.request_context(environ):
        try:
            response = app.full_dispatch_request()
        except Exception as e:
            response = app.handle_exception(e)
    
    return Response(
        response=response.get_data(),
        status=response.status_code,
        headers=dict(response.headers)
    )

if __name__ == '__main__':
    app.run(debug=True)