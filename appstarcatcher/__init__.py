# __init__.py
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
import os

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
jwt = None
limiter = None

def create_app():
    # Create Flask application
    app = Flask(__name__)

    # App configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:zxc65432@localhost/starcatcher'
    app.config['SECRET_KEY'] = '23e54cc55abaab30e316908c8fe67406ee2eda447badb2eb'
    app.config["JWT_SECRET_KEY"] = "b4b38504c6b61a7529e353a1c5b3d42b142739b23ce8ca8ac2c7770c24259bf7"
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Session settings
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['PROPAGATE_EXCEPTIONS'] = True

    # File upload settings
    app.config['UPLOAD_FOLDER_IMAGE_PLAYER'] = 'appstarcatcher/static/uploads/image_player'
    app.config['UPLOAD_FOLDER_PACKS'] = 'appstarcatcher/static/uploads/packs'
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
    app.config['UPLOAD_FOLDER'] = 'appstarcatcher/static/uploads/profile_images'
    app.config['UPLOAD_FOLDER_PROMOTIONS'] = 'appstarcatcher/static/uploads/promotions'
    app.config['UPLOAD_FOLDER_UNLIMITED'] = 'appstarcatcher/static/uploads/unlimited'

    # Create upload directories
    for folder in [
        app.config['UPLOAD_FOLDER_PROMOTIONS'],
        app.config['UPLOAD_FOLDER_UNLIMITED'],
        app.config['UPLOAD_FOLDER_IMAGE_PLAYER'],
        app.config['UPLOAD_FOLDER_PACKS'],
        app.config['UPLOAD_FOLDER']
    ]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # Initialize extensions with app
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    CORS(app)

    # Initialize JWT
    global jwt
    jwt = JWTManager(app)

    # Initialize rate limiter
    global limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["60 per minute"]
    )

    # Initialize database
    migrate = Migrate(app, db)

    # Login manager setup
    login_manager.login_view = 'login'
    login_manager.login_message = 'يرجى تسجيل الدخول للوصول إلى هذه الصفحة'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = "strong"

    with app.app_context():
        # Import models and create tables
        from appstarcatcher import models
        db.create_all()
        
        # Import and register blueprints
        from appstarcatcher.unlimited.routes import unlimited
        app.register_blueprint(unlimited, url_prefix='/unlimited')
        
        # Import routes last to avoid circular imports
        from appstarcatcher import routes

    return app

# Create the application instance
app = create_app()