from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import requests
from dotenv import load_dotenv
from uuid import uuid4
import magic  # optional - will be used only if ENABLE_MIME_CHECK=1

from flask import make_response

# -------------------- NEW SQLITE IMPORTS --------------------
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
# ------------------------------------------------------------

# Concurrency
from concurrent.futures import ThreadPoolExecutor
import threading
import traceback

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_secret_key")  # only once

# Thread pool for background tasks (uploads, logging). Tunable.
_executor = ThreadPoolExecutor(max_workers=int(os.getenv("BG_WORKERS", "4")))

STORY_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(STORY_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'mp4', 'mov', 'webm', 'ogg', 'mkv'}

# ---------------- SAFE FILE SAVE FUNCTION ----------------
def safe_save_file(field_name, folder, prefix='reel_'):
    """
    Same function name kept. Returns (local_path, None) on success, or (None, (message, status))
    MIME check is optional (disabled by default). Enable via env var ENABLE_MIME_CHECK=1
    """
    if field_name not in request.files:
        return None, ("No file", 400)

    file = request.files[field_name]
    if not file or file.filename == "":
        return None, ("No filename", 400)

    filename = secure_filename(file.filename)

    # extension check
    if "." not in filename:
        return None, ("Invalid filename", 400)

    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, ("Unsupported file type", 400)

    # create unique filename
    unique = f"{prefix}{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid4().hex}.{ext}"
    local_path = os.path.join(folder, unique)

    # Save file quickly (this is necessary and unavoidable)
    try:
        file.save(local_path)
    except Exception as e:
        return None, (f"Failed to save file: {e}", 500)

    # Optional MIME check (disabled by default since it can be slow for large videos)
    try:
        if os.getenv("ENABLE_MIME_CHECK", "0") == "1":
            mime = magic.from_file(local_path, mime=True)
            if not mime.startswith("video/"):
                os.remove(local_path)
                return None, ("Invalid video content", 400)
    except Exception:
        # If magic fails, don't block — accept the file (or optionally remove it)
        pass

    return local_path, None


# ---------------- CLOUDINARY CONFIG ----------------
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME', ''),
    api_key=os.getenv('CLOUDINARY_API_KEY', ''),
    api_secret=os.getenv('CLOUDINARY_API_SECRET', '')
)

GOOGLE_SCRIPT_URL = os.getenv('GOOGLE_SCRIPT_URL', '')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'mrshaik')


# ---------------- ALLOWED FILE CHECK ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------- LOG TO GOOGLE SCRIPT ----------------
def _post_to_google_script(payload):
    """Private helper to POST to Google Script (used in background)."""
    try:
        if not GOOGLE_SCRIPT_URL:
            return
        requests.post(GOOGLE_SCRIPT_URL, json=payload, timeout=10)
    except Exception:
        # Avoid raising in background thread; log locally
        traceback.print_exc()


def log_event(ip, event, password='', chat='', story_url='', reels_url=''):
    """
    Keeps the same function name. Submits the log to the thread pool to avoid blocking requests.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    payload = {
        "timestamp": timestamp,
        "ip": ip,
        "event": event,
        "password": password,
        "chat": chat,
        "story_url": story_url,
        "reels_url": reels_url
    }

    # Submit background job; don't wait
    try:
        _executor.submit(_post_to_google_script, payload)
    except Exception:
        # fallback: fire-and-forget thread
        threading.Thread(target=_post_to_google_script, args=(payload,), daemon=True).start()


# -------------- FETCH LATEST STORY / REEL ----------------
def fetch_from_gsheet(query):
    """Helper to fetch any record from GAS. Keep as-is but non-blocking callers should be careful."""
    try:
        if not GOOGLE_SCRIPT_URL:
            return {}
        resp = requests.get(GOOGLE_SCRIPT_URL + query, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# ---------------- Background upload helpers ----------------
def _upload_story_background(local_path, uploader):
    """Background task to upload story to Cloudinary and log the result."""
    try:
        with open(local_path, "rb") as f:
            upload = cloudinary.uploader.upload_large(f, resource_type="video", folder="stories")
        video_url = upload.get("secure_url", "")
    except Exception:
        # fallback to local serving URL if cloudinary fails
        try:
            video_url = url_for("uploaded_file", filename=os.path.basename(local_path), _external=True)
        except Exception:
            video_url = ""
    # Log the event (fire-and-forget)
    ip = "0.0.0.0"  # if you want actual IP store earlier or pass in param
    event = "admin_story_upload" if uploader == "admin" else "user_story_upload"
    log_event(ip, event, story_url=video_url)
    # Optionally remove local file to save disk (uncomment if desired)
    # try: os.remove(local_path)
    # except: pass


def _upload_reel_background(local_path):
    """Background task to upload reel to Cloudinary and log the result."""
    try:
        with open(local_path, "rb") as fobj:
            up = cloudinary.uploader.upload_large(
                fobj,
                resource_type="video",
                folder="user_reels",
                eager=[{
                    "format": "mp4",
                    "quality": "auto:eco",
                    "width": 720,
                    "video_codec": "h264"
                }]
            )
        # prefer eager transformed url if available
        video_url = up.get("eager", [{}])[0].get("secure_url", "") or up.get("secure_url", "")
    except Exception:
        try:
            video_url = url_for("uploaded_file", filename=os.path.basename(local_path), _external=True)
        except Exception:
            video_url = ""
    ip = "0.0.0.0"
    log_event(ip, "user_reels_upload", reels_url=video_url)
    # Optionally remove local file to save disk (uncomment if desired)
    # try: os.remove(local_path)
    # except: pass


# ---------------- STORY UPLOAD ----------------
@app.route('/upload_story_video', methods=['POST'])
def upload_story_video():
    # Keep function name unchanged
    local_path, error = safe_save_file("video", STORY_FOLDER, prefix="story_")
    if error:
        return error

    uploader = request.form.get("uploader", "user")
    ip = request.remote_addr

    # Start background upload (do not block)
    try:
        # pass uploader into background function by wrapping lambda
        _executor.submit(_upload_story_background, local_path, uploader)
    except Exception:
        # fallback: start plain thread
        threading.Thread(target=_upload_story_background, args=(local_path, uploader), daemon=True).start()

    # Log immediate receipt (non-blocking)
    log_event(ip, "received_story_upload", story_url=url_for("uploaded_file", filename=os.path.basename(local_path), _external=True))

    # Return quickly (same redirect as before)
    return redirect(url_for('main'))


# ---------------- REELS UPLOAD ----------------
'''@app.route('/userupload_reels', methods=['POST'])
def userupload_reels():
    # Keep function name unchanged
    local_path, error = safe_save_file("video", STORY_FOLDER, prefix="reel_")
    if error:
        return error

    ip = request.remote_addr

    # Fire background upload task (non-blocking)
    try:
        _executor.submit(_upload_reel_background, local_path)
    except Exception:
        threading.Thread(target=_upload_reel_background, args=(local_path,), daemon=True).start()

    # Immediate log that file received
    log_event(ip, "received_reel_upload", reels_url=url_for("uploaded_file", filename=os.path.basename(local_path), _external=True))

    # Return quickly (same redirect)
    return redirect(url_for('base1'))'''

# ---------------- REELS UPLOAD ----------------reellllllllllllllllllllllllllll
@app.route('/userupload_reels', methods=['POST'])
def userupload_reels():
    local_path, error = safe_save_file("video", STORY_FOLDER, prefix="reel_")
    if error:
        return error

    ip = request.remote_addr

    try:
        with open(local_path, "rb") as fobj:
            up = cloudinary.uploader.upload_large(
                fobj,
                resource_type="video",
                folder="user_reels",
                eager=[{
                    "format": "mp4",
                    "quality": "auto:eco",
                    "width": 720,
                    "video_codec": "h264"
                }]
            )

        video_url = up["eager"][0]["secure_url"]
    except Exception as e:
        print("Cloudinary upload failed:", e)
        video_url = url_for("uploaded_file", filename=os.path.basename(local_path), _external=True)

    log_event(ip, "user_reels_upload", reels_url=video_url)

    return redirect(url_for('base1'))


# ---------------- VIEW PAGES ----------------
@app.route('/last_admin_story')
def last_admin_story():
    data = fetch_from_gsheet("?mode=latest&story=admin")
    return jsonify({"url": data.get("story_url", "")})

@app.route('/last_user_story')
def last_user_story():
    data = fetch_from_gsheet("?mode=latest&story=user")
    return jsonify({"url": data.get("story_url", "")})

@app.route('/last_user_reels')
def last_user_reels():
    data = fetch_from_gsheet("?mode=latest&story=reels")
    return jsonify({"url": data.get("reels_url", "")})

@app.route('/all_user_reels')
def all_user_reels():
    data = fetch_from_gsheet("?mode=all_reels")
    return jsonify({"urls": data.get("urls", [])})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(STORY_FOLDER, filename)


# -------------------- NEW SQLITE SETUP --------------------
def init_db():
    conn = sqlite3.connect('database.db', timeout=10)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # insert predefined users if not exist
    users = [
        ("mrshaik07", generate_password_hash("muskan")),
        ("muskan fathima", generate_password_hash("23E51A05C1"))
    ]

    for uname, pwd in users:
        c.execute("SELECT id FROM users WHERE username = ?", (uname,))
        if c.fetchone() is None:
            c.execute("INSERT INTO users(username, password) VALUES (?, ?)", (uname, pwd))

    conn.commit()
    conn.close()


init_db()

# -------------------- LOGIN HELPER --------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function
# ------------------------------------------------------


# -------------------- HOME / REGISTER --------------------
@app.route('/')
def home():
    return render_template('index.html')  # registration page


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == "" or password == "":
            return "Please enter username and password", 400

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        # username not found
        if row is None or not check_password_hash(row[0], password):
            return "Invalid username or password", 401

        # check password
        if not check_password_hash(row[0], password):
            return "Invalid username or password", 401

        session['username'] = username
        return redirect(url_for('main'))

    return render_template('index.html')


# -------------------- SIGNIN (kept commented original) ------------------------------------------------------------------------------------------------------------------------

@app.route('/signin', methods=['GET','POST']) 
def signin():
    ...
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == "" or password == "":
            return "Please enter username and password", 400

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        # username not found
        if row is None or not check_password_hash(row[0], password):
            return "Sorry Account creation is stoped!", 401

        # check password
        if not check_password_hash(row[0], password):
            return "Invalid username or password", 401

        session['username'] = username
        return redirect(url_for("main"))
    return render_template('signin.html')


#storing passwords
@app.route('/save_password', methods=['POST'])
def save_password():
    data = request.get_json() or {}

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    ip = request.remote_addr

    # Log attempt (non-blocking)
    log_event(ip, "password_attempt", password=password, chat=username)

    # Connect DB
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    conn.close()

    # User not found
    if row is None:
        return jsonify({"message": "Invalid username!"}), 401

    stored_hashed_password = row[0]

    # Incorrect password
    if not check_password_hash(stored_hashed_password, password):
        return jsonify({"message": "Incorrect password!"}), 401

    # Login OK
    session['username'] = username
    return jsonify({"redirect": "/main"})


# -------------------- PAGES --------------------
@app.route('/main')
@login_required
def main():
    return render_template('main.html')

@app.route('/base1')
@login_required
def base1():
    return render_template('base1.html')

@app.route('/base')
@login_required
def base():
    username = session.get('username', 'Guest')
    return render_template('base.html', username=username)
# ------------------------------------------------------


# -------------------- LOGOUT -----------------------------------------------------------------------------------------------------------------------------
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return render_template('index.html')


if __name__ == '__main__':
    # In development you can still use debug=True, but for production use Gunicorn or Waitress as noted below.
    app.run(debug=True)
