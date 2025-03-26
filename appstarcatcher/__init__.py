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



csrf = CSRFProtect()

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    
    # إعدادات التطبيق
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/starcatcher'
    app.config['SECRET_KEY'] = '23e54cc55abaab30e316908c8fe67406ee2eda447badb2eb'
    app.config["JWT_SECRET_KEY"] = "b4b38504c6b61a7529e353a1c5b3d42b142739b23ce8ca8ac2c7770c24259bf7"  # استخدم مفتاحًا سريًا قويًا
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


    
    # إعدادات الجلسة
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # مدة صلاحية الجلسة
    app.config['SESSION_COOKIE_SECURE'] = False  # لبيئة التطوير فقط        app.config['SESSION_COOKIE_HTTPONLY'] = True  # منع الوصول عبر JavaScript
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # حماية من هجمات CSRF
    app.config['WTF_CSRF_ENABLED'] = True     #هذا يقوم بتعطيل عمل اضافة باكج جديده 
    app.config['PROPAGATE_EXCEPTIONS'] = True
    
    # إعدادات رفع الملفات
    app.config['UPLOAD_FOLDER_IMAGE_PLAYER'] = 'appstarcatcher/static/uploads/image_player'
    app.config['UPLOAD_FOLDER_PACKS'] = 'appstarcatcher/static/uploads/packs'
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
    app.config['UPLOAD_FOLDER'] = 'appstarcatcher/static/uploads/profile_images'
    
    # تهيئة قاعدة البيانات
    db.init_app(app)
    migrate = Migrate(app, db)
    
    # تهيئة مدير تسجيل الدخول
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'  # صفحة تسجيل الدخول الافتراضية
    login_manager.login_message = 'يرجى تسجيل الدخول للوصول إلى هذه الصفحة'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = "strong"  # حماية قوية للجلسة
    
    # تهيئة محدد معدل الطلبات
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["60 per minute"]
    )
    csrf.init_app(app)
    CORS(app)  # تمكين CORS لجميع النطاقات
    jwt = JWTManager(app)

    return app, login_manager, limiter

# إنشاء التطبيق والمكونات
app, login_manager, limiter = create_app()

# تهيئة قاعدة البيانات
with app.app_context():
    db.create_all()
from appstarcatcher.models import User, Player, UserPlayer, UserMarketListing, AdminMarketListing, Transaction, Pack, PackPurchase
from appstarcatcher import routes
