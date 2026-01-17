import os
import tempfile
import zipfile
import logging
import threading
import shutil
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import quote, urlparse
from functools import wraps
from typing import Optional, Dict, Any

import jwt
import requests
from flask import Flask, request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import yt_dlp
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='static')
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ==================== CONFIGURATION ====================

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    f'sqlite:///{os.path.join(BASE_DIR, "downloads.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
    raise ValueError("SECRET_KEY must be set and at least 32 characters long!")

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for security

# CORS Configuration - Restrictive in production
ALLOWED_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5000').split(',')
CORS(app, resources={
    r"/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"],
        "max_age": 3600
    }
})

# Database
db = SQLAlchemy(app)

# Socket.IO with secure configuration
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    manage_session=False
)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# Enhanced Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== SECURITY CONSTANTS ====================

AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
AUTH0_AUDIENCE = os.getenv('AUTH0_AUDIENCE')
ALGORITHMS = ["RS256"]
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# Maximum limits
MAX_URLS_PER_REQUEST = 10
MAX_URL_LENGTH = 2048
MAX_DOWNLOAD_SIZE_MB = 500
DOWNLOAD_TIMEOUT = 3600  # 1 hour

# Blocked patterns for SSRF protection
BLOCKED_HOSTS = [
    'localhost', '127.0.0.1', '0.0.0.0',
    '10.', '172.16.', '192.168.',  # Private networks
    '169.254.',  # Link-local
    'metadata.google.internal'  # Cloud metadata
]

# Cache for JWKS
jwks_cache = None
jwks_fetch_time = None
CACHE_DURATION = 86400  # 24 hours

# File cleanup tracker
download_files = {}
files_lock = threading.Lock()

# ==================== SECURITY UTILITIES ====================

def validate_url(url: str) -> bool:
    """Validate and sanitize URL to prevent SSRF attacks"""
    try:
        if not url or len(url) > MAX_URL_LENGTH:
            return False
        
        # Must start with http/https
        if not url.startswith(('http://', 'https://')):
            return False
        
        parsed = urlparse(url)
        
        # Check for blocked hosts
        hostname = parsed.hostname
        if not hostname:
            return False
        
        hostname_lower = hostname.lower()
        
        # Block localhost and private IPs
        for blocked in BLOCKED_HOSTS:
            if hostname_lower.startswith(blocked) or hostname_lower == blocked:
                logger.warning(f"Blocked URL with suspicious host: {hostname}")
                return False
        
        # Block file:// and other dangerous schemes
        if parsed.scheme not in ['http', 'https']:
            return False
        
        return True
    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    # Remove path separators and dangerous characters
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\s\-\.]', '_', filename)
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    return filename

def generate_secure_token() -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(32)

def is_safe_path(basedir: str, path: str) -> bool:
    """Check if path is within allowed directory (prevent path traversal)"""
    basedir = os.path.abspath(basedir)
    path = os.path.abspath(path)
    return path.startswith(basedir)

# ==================== AUTH0 JWT VERIFICATION ====================

def get_jwks():
    """Fetch and cache JWKS from Auth0"""
    global jwks_cache, jwks_fetch_time
    now = datetime.utcnow().timestamp()
    
    if jwks_cache is None or (jwks_fetch_time and now - jwks_fetch_time > CACHE_DURATION):
        try:
            response = requests.get(JWKS_URL, timeout=10)
            response.raise_for_status()
            jwks_cache = response.json()
            jwks_fetch_time = now
            logger.info("JWKS fetched successfully")
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise
    
    return jwks_cache

def verify_jwt(token: str) -> Dict[str, Any]:
    """Verify JWT token from Auth0 with strict validation"""
    try:
        jwks = get_jwks()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                break

        if not rsa_key:
            raise ValueError("Public key not found in JWKS")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require_exp": True,
                "require_iat": True
            }
        )
        return payload
    
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidAudienceError:
        raise ValueError("Invalid audience")
    except jwt.InvalidIssuerError:
        raise ValueError("Invalid issuer")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"JWT verification error: {e}")
        raise ValueError(f"Token verification failed: {str(e)}")

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning(f"Missing auth header from {get_remote_address()}")
            return jsonify({"error": "Authorization required"}), 401

        try:
            token = auth_header.split(" ")[1]
            payload = verify_jwt(token)
            request.user_id = payload["sub"]
            logger.info(f"Authenticated request from user: {request.user_id[:10]}...")
        except ValueError as e:
            logger.warning(f"Auth failed from {get_remote_address()}: {e}")
            return jsonify({"error": str(e)}), 401
        except Exception as e:
            logger.error(f"Unexpected auth error: {e}")
            return jsonify({"error": "Authentication failed"}), 401

        return f(*args, **kwargs)
    
    return decorated

# ==================== DATABASE MODEL ====================

class DownloadHistory(db.Model):
    __tablename__ = 'download_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    title = db.Column(db.String(500))
    file_format = db.Column(db.String(10), nullable=False)
    quality = db.Column(db.String(20))
    file_size = db.Column(db.String(20))
    download_path = db.Column(db.String(500))
    download_token = db.Column(db.String(64), unique=True, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default='completed')
    ip_address = db.Column(db.String(45))

    def as_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'title': self.title,
            'file_format': self.file_format,
            'quality': self.quality,
            'file_size': self.file_size,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'status': self.status,
            'download_token': self.download_token
        }

with app.app_context():
    db.create_all()

def clean_old_history(user_id: Optional[str] = None, days: int = 30):
    """Clean old download history and associated files"""
    try:
        threshold = datetime.utcnow() - timedelta(days=days)
        query = DownloadHistory.query.filter(DownloadHistory.timestamp < threshold)
        
        if user_id:
            query = query.filter(DownloadHistory.user_id == user_id)
        
        old_records = query.all()
        
        # Delete associated files
        for record in old_records:
            if record.download_path and os.path.exists(record.download_path):
                try:
                    # Check if it's in a temp directory
                    if record.download_path.startswith(tempfile.gettempdir()):
                        if os.path.isfile(record.download_path):
                            os.remove(record.download_path)
                        elif os.path.isdir(record.download_path):
                            shutil.rmtree(record.download_path)
                except Exception as e:
                    logger.error(f"Error deleting file {record.download_path}: {e}")
        
        deleted = query.delete()
        db.session.commit()
        logger.info(f"Cleaned {deleted} old history records")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cleaning history: {e}")

# ==================== FILE CLEANUP ====================

def schedule_file_cleanup(filepath: str, delay: int = 3600):
    """Schedule file cleanup after delay"""
    def cleanup():
        import time
        time.sleep(delay)
        try:
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    os.remove(filepath)
                elif os.path.isdir(filepath):
                    shutil.rmtree(filepath)
                logger.info(f"Cleaned up file: {filepath}")
        except Exception as e:
            logger.error(f"Error cleaning up file {filepath}: {e}")
    
    threading.Thread(target=cleanup, daemon=True).start()

# ==================== DOWNLOAD LOGIC ====================

def progress_hook(d, download_id):
    """Hook for download progress updates"""
    try:
        if d['status'] == 'downloading':
            percent = d.get('_percent_str', '0%').strip()
            speed = d.get('_speed_str', 'N/A').strip()
            eta = d.get('_eta_str', 'N/A').strip()
            downloaded = d.get('_downloaded_bytes_str', '0B').strip()
            total = d.get('_total_bytes_str', 'Unknown').strip()
            
            socketio.emit('download_progress', {
                'download_id': download_id,
                'percent': percent,
                'speed': speed,
                'eta': eta,
                'downloaded': downloaded,
                'total': total,
                'status': 'Downloading'
            })
            
        elif d['status'] == 'finished':
            socketio.emit('download_progress', {
                'download_id': download_id,
                'percent': '100%',
                'status': 'Processing...'
            })
            
    except Exception as e:
        logger.error(f"Error in progress hook: {e}")

def download_single(url: str, file_format: str, quality: str, output_path: str, download_id: str):
    """Download a single media file with security checks"""
    try:
        # Validate URL
        if not validate_url(url):
            raise ValueError("Invalid or blocked URL")
        
        base_opts = {
            'outtmpl': os.path.join(output_path, '%(title)s.%(ext)s'),
            'progress_hooks': [lambda d: progress_hook(d, download_id)],
            'quiet': False,
            'no_warnings': False,
            'nocheckcertificate': True,
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'retries': 10,
            'fragment_retries': 10,
            'continuedl': True,
            'socket_timeout': 30,
            'max_filesize': MAX_DOWNLOAD_SIZE_MB * 1024 * 1024,  # Enforce size limit
            'age_limit': None,
            'extractor_args': {'youtube': {'skip': ['dash', 'hls']}},  # Optimize
        }

        quality_formats = {
            '2160p': 'bestvideo[height<=2160]+bestaudio/best',
            '1440p': 'bestvideo[height<=1440]+bestaudio/best',
            '1080p': 'bestvideo[height<=1080]+bestaudio/best',
            '720p': 'bestvideo[height<=720]+bestaudio/best',
            '480p': 'bestvideo[height<=480]+bestaudio/best',
            '360p': 'bestvideo[height<=360]+bestaudio/best',
            'best': 'bestvideo+bestaudio/best'
        }
        
        audio_quality = {
            '320kbps': '320',
            '256kbps': '256',
            '192kbps': '192',
            '128kbps': '128',
            'best': '0'
        }
        
        # Validate format
        allowed_formats = ['mp4', 'mp3', 'wav', 'jpg', 'png']
        if file_format not in allowed_formats:
            raise ValueError(f"Invalid format: {file_format}")
        
        if file_format == 'mp4':
            format_str = quality_formats.get(quality, 'bestvideo+bestaudio/best')
            ydl_opts = {**base_opts, 'format': format_str, 'merge_output_format': 'mp4'}
            
        elif file_format == 'mp3':
            quality_val = audio_quality.get(quality, '192')
            ydl_opts = {
                **base_opts,
                'format': 'bestaudio/best',
                'postprocessors': [{
                    'key': 'FFmpegExtractAudio',
                    'preferredcodec': 'mp3',
                    'preferredquality': quality_val,
                }]
            }
            
        elif file_format == 'wav':
            ydl_opts = {
                **base_opts,
                'format': 'bestaudio/best',
                'postprocessors': [{'key': 'FFmpegExtractAudio', 'preferredcodec': 'wav'}]
            }
            
        elif file_format in ['jpg', 'png']:
            thumbnail_format = 'jpg' if file_format == 'jpg' else 'png'
            ydl_opts = {
                **base_opts,
                'skip_download': True,
                'writethumbnail': True,
                'postprocessors': [{
                    'key': 'FFmpegThumbnailsConvertor',
                    'format': thumbnail_format
                }]
            }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            title = sanitize_filename(info.get('title', 'Unknown'))
            
            if file_format in ['jpg', 'png']:
                thumbnail = info.get('thumbnails', [{}])[-1].get('filepath')
                final_path = thumbnail if thumbnail and os.path.exists(thumbnail) else None
            else:
                requested = info.get('requested_downloads', [])
                final_path = requested[0].get('filepath') if requested else None
            
            if not final_path or not os.path.exists(final_path):
                raise FileNotFoundError('Downloaded file not found')
            
            # Verify file is within allowed directory
            if not is_safe_path(output_path, final_path):
                logger.error(f"Path traversal attempt detected: {final_path}")
                raise ValueError("Invalid file path")
            
            file_size_mb = f"{os.path.getsize(final_path) / (1024*1024):.2f} MB"
            
            return {
                'path': final_path,
                'title': title,
                'size': file_size_mb
            }
            
    except Exception as e:
        logger.error(f"Download error for {url}: {str(e)}")
        socketio.emit('download_error', {
            'download_id': download_id,
            'error': str(e)
        })
        raise

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Serve main page"""
    return app.send_static_file('index.html')

@app.route('/health')
@limiter.limit("30 per minute")
def health():
    """Health check endpoint"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except:
        db_status = 'unhealthy'
    
    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/download_file')
@limiter.limit("20 per minute")
@require_auth
def download_file():
    """Serve downloaded file with authentication and token verification"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'Download token required'}), 400
    
    try:
        # Find record by token and verify ownership
        record = DownloadHistory.query.filter_by(
            download_token=token,
            user_id=request.user_id
        ).first()
        
        if not record:
            logger.warning(f"Invalid download token from {get_remote_address()}")
            return jsonify({'error': 'Invalid or expired download link'}), 404
        
        filepath = record.download_path
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        # Verify path safety
        if not is_safe_path(tempfile.gettempdir(), filepath):
            logger.error(f"Path traversal attempt: {filepath}")
            return jsonify({'error': 'Invalid file path'}), 403
        
        filename = sanitize_filename(os.path.basename(filepath))
        
        # Log download
        logger.info(f"File downloaded: {filename} by user {request.user_id[:10]}...")
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            max_age=0  # Disable caching
        )
        
    except Exception as e:
        logger.error(f"Error serving file: {e}")
        return jsonify({'error': 'Error serving file'}), 500

@app.route('/download', methods=['POST'])
@limiter.limit("10 per minute")
def download():
    """Main download endpoint with strict validation"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request'}), 400
        
        urls_input = data.get('urls', [])
        file_format = data.get('format', '').lower()
        quality = data.get('quality', '').lower()
        custom_path = data.get('path', '')
        
        # Validation
        if not urls_input or not file_format:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        if len(urls_input) > MAX_URLS_PER_REQUEST:
            return jsonify({'error': f'Maximum {MAX_URLS_PER_REQUEST} URLs allowed'}), 400
        
        # Validate all URLs
        for url in urls_input:
            if not validate_url(url):
                return jsonify({'error': f'Invalid or blocked URL: {url[:50]}...'}), 400
        
        # Validate format
        allowed_formats = ['mp4', 'mp3', 'wav', 'jpg', 'png']
        if file_format not in allowed_formats:
            return jsonify({'error': 'Invalid format'}), 400
        
        # Handle custom path securely
        if custom_path:
            if not os.path.exists(custom_path) or not os.path.isdir(custom_path):
                return jsonify({'error': 'Invalid custom path'}), 400
            output_path = custom_path
            is_temp = False
        else:
            output_path = tempfile.mkdtemp(prefix='just_paste_')
            is_temp = True
        
        results = []
        errors = []

        # Get user ID if authenticated
        user_id = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            try:
                token = auth_header.split(' ')[1]
                payload = verify_jwt(token)
                user_id = payload['sub']
                clean_old_history(user_id)
            except:
                pass  # Guest download

        def threaded_download(idx, url):
            download_id = f"download_{idx}_{int(datetime.now().timestamp() * 1000)}"
            try:
                result = download_single(url, file_format, quality, output_path, download_id)
                
                # Generate secure download token
                download_token = generate_secure_token()
                
                if user_id:
                    with app.app_context():
                        record = DownloadHistory(
                            user_id=user_id,
                            url=url,
                            title=result['title'],
                            file_format=file_format,
                            quality=quality,
                            file_size=result['size'],
                            download_path=result['path'],
                            download_token=download_token,
                            status='completed',
                            ip_address=get_remote_address()
                        )
                        db.session.add(record)
                        db.session.commit()
                
                results.append({
                    'url': url,
                    'title': result['title'],
                    'path': result['path'],
                    'size': result['size'],
                    'token': download_token if user_id else None
                })
                
                socketio.emit('download_complete', {
                    'download_id': download_id,
                    'title': result['title'],
                    'token': download_token if user_id else None
                })
                
            except Exception as e:
                errors.append({'url': url, 'error': str(e)})
                logger.error(f"Error downloading {url}: {str(e)}")

        threads = []
        for idx, url in enumerate(urls_input):
            t = threading.Thread(target=threaded_download, args=(idx, url))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=DOWNLOAD_TIMEOUT)

        response_data = {
            'success': len(errors) == 0,
            'results': results,
            'errors': errors
        }

        if results and is_temp:
            if len(results) > 1:
                zip_filename = f"just_paste_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                zip_path = os.path.join(output_path, sanitize_filename(zip_filename))
                
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for res in results:
                        safe_title = sanitize_filename(res['title'])
                        arcname = f"{safe_title}.{file_format}"
                        zf.write(res['path'], arcname=arcname)
                
                response_data['download_type'] = 'zip'
                response_data['download_url'] = f"/download_file?token={results[0]['token']}"
            else:
                response_data['download_type'] = 'single'
                response_data['download_url'] = f"/download_file?token={results[0]['token']}"
            
            # Schedule cleanup
            schedule_file_cleanup(output_path, 3600)
        elif custom_path:
            response_data['path'] = output_path

        return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"Download endpoint error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/history', methods=['GET'])
@limiter.limit("30 per minute")
@require_auth
def history():
    """Get user download history"""
    try:
        user_id = request.user_id
        clean_old_history(user_id)
        
        records = DownloadHistory.query.filter_by(
            user_id=user_id
        ).order_by(
            DownloadHistory.timestamp.desc()
        ).limit(100).all()
        
        return jsonify([r.as_dict() for r in records])
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        return jsonify({'error': 'Failed to fetch history'}), 500

@app.route('/clear_history', methods=['POST'])
@limiter.limit("5 per hour")
@require_auth
def clear_history():
    """Clear all user history"""
    try:
        user_id = request.user_id
        
        # Get all records to delete files
        records = DownloadHistory.query.filter_by(user_id=user_id).all()
        
        for record in records:
            if record.download_path and os.path.exists(record.download_path):
                try:
                    if record.download_path.startswith(tempfile.gettempdir()):
                        if os.path.isfile(record.download_path):
                            os.remove(record.download_path)
                except Exception as e:
                    logger.error(f"Error deleting file: {e}")
        
        DownloadHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        logger.info(f"History cleared for user {user_id[:10]}...")
        return jsonify({'status': 'History cleared'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing history: {e}")
        return jsonify({'error': 'Failed to clear history'}), 500

@app.route('/delete_history/<int:record_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@require_auth
def delete_history(record_id):
    """Delete specific history record"""
    try:
        user_id = request.user_id
        
        record = DownloadHistory.query.filter_by(
            id=record_id,
            user_id=user_id
        ).first()
        
        if not record:
            return jsonify({'error': 'Record not found'}), 404
        
        # Delete file
        if record.download_path and os.path.exists(record.download_path):
            try:
                if record.download_path.startswith(tempfile.gettempdir()):
                    if os.path.isfile(record.download_path):
                        os.remove(record.download_path)
            except Exception as e:
                logger.error(f"Error deleting file: {e}")
        
        db.session.delete(record)
        db.session.commit()
        
        return jsonify({'status': 'Record deleted'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting record: {e}")
        return jsonify({'error': 'Failed to delete record'}), 500

@app.route('/validate_path', methods=['POST'])
@limiter.limit("20 per minute")
def validate_path():
    """Validate custom download path"""
    try:
        data = request.get_json()
        path = data.get('path', '').strip()
        
        if not path:
            return jsonify({'valid': False, 'message': 'Path cannot be empty'})
        
        # Security checks
        if len(path) > 500:
            return jsonify({'valid': False, 'message': 'Path too long'})
        
        # Check for path traversal attempts
        if '..' in path or path.startswith('~'):
            return jsonify({'valid': False, 'message': 'Invalid path format'})
        
        if os.path.exists(path) and os.path.isdir(path):
            # Check write permissions
            if os.access(path, os.W_OK):
                return jsonify({'valid': True, 'message': 'Path is valid and writable'})
            else:
                return jsonify({'valid': False, 'message': 'No write permission'})
        else:
            return jsonify({'valid': False, 'message': 'Path does not exist or is not a directory'})
            
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return jsonify({'valid': False, 'message': 'Error validating path'})

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({'error': 'Request too large'}), 413

# ==================== SECURITY HEADERS ====================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.auth0.com https://threejs.org; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; connect-src 'self' https://*.auth0.com"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ==================== STARTUP ====================

if __name__ == '__main__':
    # Production check
    if not os.getenv('SECRET_KEY') or len(os.getenv('SECRET_KEY')) < 32:
        logger.error("SECRET_KEY not properly set!")
        exit(1)
    
    if not AUTH0_DOMAIN or not AUTH0_AUDIENCE:
        logger.error("Auth0 configuration missing!")
        exit(1)
    
    # Log startup
    logger.info("=" * 50)
    logger.info("Just Paste Server Starting...")
    logger.info(f"Environment: {'Production' if not app.debug else 'Development'}")
    logger.info("=" * 50)
    
    # Use gunicorn in production
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)